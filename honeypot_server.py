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
from datetime import datetime
import os
from scapy.all import *
import netifaces as ni
from scapy.all import IP
import threading
from tqdm import tqdm
import atexit
import signal
from threading import Lock


# Global variables for process management
SOURCE_IP = None
SOURCE_MAC = None
TARGET_IP = None
IFACE_NAME = 'eth0'
PATTERN_TO_REPLAY = None
PREPROCESSED = None

stop_flag = True
stop_flag_lock = Lock()
current_replay_process: Optional[subprocess.Popen] = None
replay_thread = None
checker_thread = None
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
    if current_replay_process is not None:
        os.killpg(os.getpgid(current_replay_process.pid), 15)
        current_replay_process = None


def handle_sigterm(signum, frame):
    cleanup()
    os._exit(0)  # Force exit


def get_static_source_ip_address(interface=IFACE_NAME):
    try:
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        return ip
    except ValueError:
        return "Interface not found"


def get_source_mac(interface=IFACE_NAME):
    try:
        mac_address = ni.ifaddresses(interface)[ni.AF_LINK][0]['addr']
        return mac_address
    except ValueError:
        return "Interface not found"
    

def modify_and_save_pcap(input_pcap_file, output_pcap_file):
    # Read the PCAP file
    print(f'Opening {input_pcap_file} file, please wait...')
    packets = rdpcap(input_pcap_file)
    print('File opened!')
    print(f'Now rewritting packets with source {SOURCE_IP} and dest {TARGET_IP}')
    # Modify source and destination IP addresses of each packet
    for packet in tqdm(packets):
        if IP in packet:
            packet[IP].src = SOURCE_IP
            packet[IP].dst = TARGET_IP
    print(f'Packets re-written. NOW SAVING, please wait...')
    # Save the modified packets to another PCAP file
    wrpcap(output_pcap_file, packets)
    print(f'File saved! ready to go!!')


def resend_pcap_with_modification_tcpreplay():
    global current_replay_process, stop_flag, rewriting
    
    original_pcap_file = os.path.join(f"{PATTERN_TO_REPLAY}/{PATTERN_TO_REPLAY}.pcap")
    file_to_replay = f"{PATTERN_TO_REPLAY}/{PATTERN_TO_REPLAY}-from{SOURCE_IP}to{TARGET_IP}.pcap"
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
    cmd = f"tcpreplay -i {IFACE_NAME} --stats 3 {file_to_replay}"
    
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


def start_replay_with_monitor():
    """Starts the replay function and the monitor in separate threads"""
   
    # Create and start threads
    replay_thread = threading.Thread(
        target=resend_pcap_with_modification_tcpreplay,
        daemon=True)
    checker_thread = threading.Thread(
        target=process_checker,
        daemon=True)
    
    replay_thread.start()
    checker_thread.start()
    
    return replay_thread, checker_thread


@app.get("/")
async def root():
    logger.info("Root endpoint called")
    return {"message": "Hello World"}


@app.get("/items/{item_id}")
async def read_item(item_id: int):
    logger.info(f"Item requested with id: {item_id}")
    return {"item_id": item_id, "timestamp": datetime.now().isoformat()}


@app.post("/items/")
async def create_item(item: dict):
    logger.info(f"Creating new item: {item}")
    return {"item": item, "created": True}


@app.get("/health")
async def health_check():
    logger.debug("Health check endpoint called")
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/replay")
async def start_replay(kwargs: dict):
    global PATTERN_TO_REPLAY, TARGET_IP, SOURCE_IP, SOURCE_MAC, stop_flag
    global replay_thread, checker_thread
    logger.info("Replay endpoint called")

    if not stop_flag:
        logger.info("Replay already in progress.")
        return {"message": "Replay already in progress."}
    
    PATTERN_TO_REPLAY = kwargs.get('pattern', None)
    TARGET_IP = kwargs.get('dest_ip', None)

    # Your new source IP
    SOURCE_IP = get_static_source_ip_address()
    SOURCE_MAC = get_source_mac()

    logger.debug(f'Source IP {SOURCE_IP}')
    logger.debug(f'Source MAC {SOURCE_MAC}')
    logger.debug(f'Target IP {TARGET_IP}')
    logger.debug(f'Pattern to replay: {PATTERN_TO_REPLAY}')

    with stop_flag_lock:
        stop_flag = False
    
    replay_thread, checker_thread = start_replay_with_monitor()  # Execute the function immediately

    return {"status": "Replay started", "pattern": PATTERN_TO_REPLAY, "target": TARGET_IP}


@app.get("/replay_status")
async def get_replay_status():
    logger.info("Replay status endpoint called")
    if current_replay_process is None:
        return {"status": "stopped"}
    else:
        return {"status": "running"}


@app.post("/stop")
async def stop_replay_endpoint():
    global stop_flag, replay_thread, checker_thread
    logger.info("Stop replay endpoint called")
    if stop_flag:
        logger.info("Replay already stopped.")
        return {"message": "Replay already stopped."}
    if rewriting:
        logger.info("Replay is currently rewriting the pcap file. Please wait.")
        return {"message": "Replay is currently rewriting the pcap file. Please wait."}
    with stop_flag_lock:
        stop_flag = True
    if replay_thread:
        replay_thread.join()
    if checker_thread:
        checker_thread.join()
    logger.info("Replay stopped.")
    return {"message": "Replay stopped."}



if __name__ == "__main__":
    logger.info("Starting HONEYPOT FASTAPI server")

    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
    


