# This file is part of the "Smartville" project.
# Copyright (c) 2024 University of Insubria
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0
# For the full text of the license, visit:
# https://www.apache.org/licenses/LICENSE-2.0

# Smartville is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# Apache License 2.0 for more details.

# You should have received a copy of the Apache License 2.0
# along with Smartville. If not, see <https://www.apache.org/licenses/LICENSE-2.0>.

# Additional licensing information for third-party dependencies
# used in this file can be found in the accompanying `NOTICE` file.

import logging
from fastapi import FastAPI
import uvicorn
import os
from scapy.all import *
import netifaces as ni
from scapy.all import IP
import threading
import atexit
import signal
from threading import Lock
import shlex
from health_monitor import HealthMonitor
import time
import subprocess



# Global variables for process management
SOURCE_IP = None
SOURCE_MAC = None
TARGET_IP = None
IFACE_NAME = 'eth0'
PATTERN_TO_REPLAY = None
PREPROCESSED = None
SPEED_MULTIPLIER = None
HEALTH_MONITORING = None
KAFKA_ENDPOINT = None
HEALTH_PROBE_FREQUENCY = None


health_monitor = None
kafka_msg_producer = None
healt_probes_count = 0
stop_flag = True
stop_flag_lock = Lock()
current_replay_process: Optional[subprocess.Popen] = None
replay_thread = None
checker_thread = None
health_thread = None
rewriting = False

logger = logging.getLogger("honeypot_server")
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api.log"),
        logging.StreamHandler()
    ]
)

app = FastAPI(title="Honeypot Server API", description="API for simulating honeypots")


def cleanup():
    global stop_flag, current_replay_process
    logger.info("Cleaning up before exit")
    with stop_flag_lock:
        stop_flag = True
    stop_replay_endpoint()
    if current_replay_process is not None:
        os.killpg(os.getpgid(current_replay_process.pid), 15)
        current_replay_process = None
    if 'health_monitor' in globals() and health_monitor is not None:
        health_monitor.stop()
        health_monitor.cleanup_kafka()
        

def handle_sigterm(signum, frame):
    cleanup()
    os._exit(0)  # Force exit


def get_static_source_ip_address(interface=IFACE_NAME):
    try:
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        return ip
    except ValueError:
        return "Interface not found"


def get_iface_mac(iface=IFACE_NAME):
    try:
        return ni.ifaddresses(iface)[ni.AF_LINK][0]['addr']
    except (ValueError, KeyError):
        raise RuntimeError(f"Could not get MAC for {iface}")
    

def get_source_mac(interface=IFACE_NAME):
    try:
        mac_address = ni.ifaddresses(interface)[ni.AF_LINK][0]['addr']
        return mac_address
    except ValueError:
        return "Interface not found"

def detect_ips(pcap_file, max_packets=1000):
    """
    Quickly scan a PCAP for unique source/dest IPs.
    Stops after max_packets for speed.
    """
    src_ips, dst_ips = set(), set()
    with PcapReader(pcap_file) as reader:
        for i, pkt in enumerate(reader):
            if IP in pkt:
                src_ips.add(pkt[IP].src)
                dst_ips.add(pkt[IP].dst)
            if i >= max_packets:
                break
    return list(src_ips), list(dst_ips)


def modify_and_save_pcap(input_pcap_file, output_pcap_file):
    """
    Detect old src/dst IPs in the PCAP and rewrite them to new_src/new_dst
    using tcprewrite.
    """
    src_ips, dst_ips = detect_ips(input_pcap_file)

    if not src_ips or not dst_ips:
        raise RuntimeError("No IP addresses detected in the PCAP")


    # get MAC from iface
    new_src_mac = get_iface_mac()
    print(f"Using new_src_ip={SOURCE_IP}, new_dst_ip={TARGET_IP}, new_src_mac={new_src_mac}")


    cmd = (
        f"tcprewrite --srcipmap=0.0.0.0/0:{SOURCE_IP} "
        f"--dstipmap=0.0.0.0/0:{TARGET_IP} "
        f"--enet-smac={new_src_mac} "
        f"--fixcsum --infile={shlex.quote(input_pcap_file)} "
        f"--outfile={shlex.quote(output_pcap_file)}"
    )

    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("tcprewrite failed:\n", result.stderr)
        raise RuntimeError("tcprewrite failed")
    print("PCAP rewrite complete:", output_pcap_file)


def resend_pcap_with_modification_tcpreplay():
    global stop_flag

    if PATTERN_TO_REPLAY == 'doorlock':
        for i in range(1,4):
            original_pcap_file = os.path.join(f"{PATTERN_TO_REPLAY}/{PATTERN_TO_REPLAY}_{i}.pcap")
            file_to_replay = f"{PATTERN_TO_REPLAY}/{PATTERN_TO_REPLAY}_{i}-from{SOURCE_IP}to{TARGET_IP}.pcap"
            if not stop_flag:
                rewrite_and_send(original_pcap_file,file_to_replay)

    else:

        original_pcap_file = os.path.join(f"{PATTERN_TO_REPLAY}/{PATTERN_TO_REPLAY}.pcap")
        file_to_replay = f"{PATTERN_TO_REPLAY}/{PATTERN_TO_REPLAY}-from{SOURCE_IP}to{TARGET_IP}.pcap"
        rewrite_and_send(original_pcap_file,file_to_replay)


def rewrite_and_send(original_pcap_file, file_to_replay):
    global rewriting, current_replay_process, stop_flag
    rewriting = False

    if not os.path.exists(file_to_replay):
        logger.info(f'FILE NOT FOUND: {file_to_replay}. Will rewrite pattern with new addresses first...')
        # Modify and send packets using tcpreplay
        rewriting = True
        modify_and_save_pcap(original_pcap_file, file_to_replay)
        rewriting = False
    else:
        logger.info(f'REWRITEN {PATTERN_TO_REPLAY} PATTERN FOUND from {SOURCE_IP} to {TARGET_IP}')

    print('sending...')
    # Tcpreplay command to send the modified packets
    cmd = f"tcpreplay -i {IFACE_NAME} -x {SPEED_MULTIPLIER} --stats 3 {file_to_replay}"
    
    while not stop_flag:
        # Use Popen instead of run to have more control over the process
        current_replay_process = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
        current_replay_process.wait()  # Wait for process to complete
        current_replay_process = None  # Clear when done

        logger.info("Replay process completed or terminated from api.")
        if not stop_flag: logging.info("Recommencing replay.")


def process_checker():
    """Checks every second if stop_flag is True and kills the process if needed"""
    global current_replay_process

    while not stop_flag:
        time.sleep(1)
        
    if current_replay_process is not None:
        print("Stop flag detected, terminating tcpreplay process...")
        # Kill the process group to ensure all child processes are terminated
        os.killpg(os.getpgid(current_replay_process.pid), 15)  # 15 is SIGTERM
        current_replay_process = None
        logger.info("Replay process stopped.")


def start_replaying_threads():
    """Starts the replay function and the monitor in separate threads"""
    health_thread = None

    # Create and start threads
    replay_thread = threading.Thread(
        target=resend_pcap_with_modification_tcpreplay,
        daemon=True)
    checker_thread = threading.Thread(
        target=process_checker,
        daemon=True)
    
    replay_thread.start()
    checker_thread.start()


    if HEALTH_MONITORING:
        health_thread = threading.Thread(
            target=health_probes_thread,
            daemon=True
        )

        health_thread.start()
    
    return replay_thread, checker_thread, health_thread


def health_probes_thread():
    global stop_flag, health_monitor, HEALTH_PROBE_FREQUENCY

    logger.info(f"Starting health probes thread for node: {SOURCE_IP}")

    while not stop_flag:
        if health_monitor.alive:
            health_monitor.probe_and_send()
        else:
            logger.warning("Health monitor is not initialized. Skipping health probe.")
        # Use event.wait so a stop() call unblocks this immediately
        health_monitor._stop_event.wait(HEALTH_PROBE_FREQUENCY)
    health_monitor.cleanup_kafka()   # this does flush + topic deletion



@app.post("/replay")
async def start_replay(kwargs: dict):
    global PATTERN_TO_REPLAY, TARGET_IP, SOURCE_IP, SOURCE_MAC, SPEED_MULTIPLIER, stop_flag, HEALTH_MONITORING
    global kafka_msg_producer, replay_thread, checker_thread, health_thread, health_monitor, HEALTH_PROBE_FREQUENCY
    logger.info("Replay endpoint called")

    
    HEALTH_MONITORING = kwargs.get('health_monitoring', False)
    KAFKA_ENDPOINT = kwargs.get('kafka_endpoint', None)
    PATTERN_TO_REPLAY = kwargs.get('pattern', None)
    TARGET_IP = kwargs.get('dest_ip', None)
    SOURCE_IP = get_static_source_ip_address()
    SOURCE_MAC = get_source_mac()
    SPEED_MULTIPLIER = kwargs.get('speed_multiplier')

    if 'internal_ips' in kwargs:
        internal_ips = kwargs['internal_ips']
        if internal_ips:
            os.environ['no_proxy'] = ','.join(internal_ips)

    if HEALTH_MONITORING:
        health_params = kwargs.get('health_params', {})
        health_params['host_ip'] = SOURCE_IP
        health_params['logger'] = logger
        health_params['bootstrap_server'] = KAFKA_ENDPOINT
        health_params['mockserver_url']  = kwargs['mockserver_url']
        health_monitor = HealthMonitor(health_params)
        HEALTH_PROBE_FREQUENCY = health_params['probe_frequency_seconds']

    if not stop_flag:
        logger.info("Replay already in progress.")
        return {"message": f"Already processing {PATTERN_TO_REPLAY}"}

    

    logger.info(f'Source IP {SOURCE_IP}')
    logger.info(f'Source MAC {SOURCE_MAC}')
    logger.info(f'Target IP {TARGET_IP}')
    logger.info(f'Pattern to replay: {PATTERN_TO_REPLAY}')
    logger.info(f'Speed Multiplier: {SPEED_MULTIPLIER}')


    with stop_flag_lock:
        stop_flag = False
    
    replay_thread, checker_thread, health_thread = start_replaying_threads()  # Execute the function immediately

    return {"message": f"Started replaying {PATTERN_TO_REPLAY} to {TARGET_IP}"}


@app.get("/replay_status")
async def get_replay_status():
    logger.info("Replay status endpoint called")
    if current_replay_process is None:
        return {"message": "Replay not running"}
    else:
        return {"message": "Replay running"}


@app.post("/stop")
async def stop_replay_endpoint():
    global stop_flag, replay_thread, checker_thread, health_thread
    logger.info("Stop replay endpoint called")
    if stop_flag:
        logger.info("Replay already stopped.")
        return {"message": "Replay already stopped."}
    if rewriting:
        logger.info("Replay is currently rewriting the pcap file. Please wait.")
        return {"message": "Replay is currently rewriting the pcap file. Please wait."}
    with stop_flag_lock:
        stop_flag = True
    if health_monitor and HEALTH_MONITORING:
        health_monitor.stop()  # unblocks _stop_event.wait() immediately
        health_monitor.cleanup_kafka()  # belt-and-suspenders in case thread crashed
    if replay_thread:
        replay_thread.join()
    if checker_thread:
        checker_thread.join()
    if health_thread:
        health_thread.join()
    logger.info("Replay stopped.")
    return {"message": "Replay stopped."}



if __name__ == "__main__":
    logger.info("Starting HoneyPot FastAPI server")

    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)
    
    try:
        port = int(os.environ.get("SERVER_PORT"))
    except Exception as e:
        print(f"Error parsing SERVER_PORT env var: {e}")
        assert False

    uvicorn.run(app, host="0.0.0.0", port=port)