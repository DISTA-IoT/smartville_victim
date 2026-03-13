import time
import psutil
import subprocess
import math
import socket
import requests
import threading
from confluent_kafka.admin import AdminClient, NewTopic
from confluent_kafka import KafkaException
from confluent_kafka import Producer, SerializingProducer
from confluent_kafka.serialization import StringSerializer
import json
import os
import statistics
import re
import urllib.request

CPU = "CPU"
RAM = "RAM"
RTT = "RTT"
INBOUND = "INBOUND"
OUTBOUND = "OUTBOUND"
HEALTH = "HEALTH"

        
class HealthMonitor():


    def __init__(self, kwargs):
        self.kwargs = kwargs
        self.topic_name = kwargs['host_ip']
        self.logger = kwargs['logger']
        self.ping_thread_timeout = kwargs['ping_thread_timeout']
        self.ping_host = kwargs['ping_host']
        self.probe_frequency_seconds = kwargs['probe_frequency_seconds']
        self.stopme = False
        self._stop_event = threading.Event()
        self.metrics = kwargs['probe_metrics']
        self.bootstrap_server = kwargs['bootstrap_server']
        self.max_conn_retries = kwargs['max_conn_retries']
        self.controller_server_url = kwargs['controller_server_url']
        self.other_configs = kwargs
        self.alive = False
        self.producer = None
        self._psutil_process = psutil.Process()  # cache the process object
        self._psutil_process.cpu_percent(interval=0.1)
        self.cpu_count = os.cpu_count()
        self.conf_prod = {
            'bootstrap.servers': self.bootstrap_server,
            'key.serializer': StringSerializer('utf_8'),
            'value.serializer': lambda x, ctx: json.dumps(x).encode('utf-8')
            }
        self.add_ip_to_no_proxy_env_var(self.controller_server_url)
        
        if self.check_kafka_server():
            if self.create_topic():
                self.producer = SerializingProducer(self.conf_prod)
                self.alive = True
                self.logger.info(f"Node HealthMonitor initialized. Will probe {self.metrics} every {self.probe_frequency_seconds} seconds.")
                self.reset()
            else:
                raise RuntimeError(f"Could not find Kafka broker at {self.bootstrap_server}.")
                

    def add_ip_to_no_proxy_env_var(self, some_ip):
        no_proxy = os.environ.get('no_proxy', '')
        if no_proxy != '':
            no_proxy += ','
        no_proxy += some_ip
        os.environ['no_proxy'] = no_proxy
        self.logger.info(f"Fixed no_proxy to {no_proxy}")


    def create_topic(self):
        if self.topic_exists():
            self.logger.info(f"Topic {self.topic_name} already exists.")
            return True
        else:
            new_topic = NewTopic(
                self.topic_name, 
                1, # number of partitions
                self.other_configs['topic_replication_factor'])

            self.admin_client.create_topics([new_topic])
            try:
                time.sleep(10)
            except Exception as e:
                self.logger.error(f"Error while creating topic '{self.topic_name}': {e}")
                return False

            self.logger.info(f"Topic {self.topic_name} created.")
            return True


    def topic_exists(self):
        try:
            metadata = self.admin_client.list_topics(timeout=10)
            topics = metadata.topics

            if self.topic_name in topics:
                return True
            else:
                return False

        except KafkaException as e:
            self.logger.error(f"Error: {e}")
            return False 
        

    def check_kafka_server(self):
        kafka_check = False

        while not kafka_check and self.max_conn_retries > 0:
            self.max_conn_retries -= 1

            if self.server_exist():
                try:
                    #consumer_conf = {'bootstrap.servers': bootstrap_servers, 'group.id': 'my-group'}
                    conf = {'bootstrap.servers': self.bootstrap_server}
                    #consumer = Consumer(consumer_conf)
                    self.admin_client = AdminClient(conf)
                    _ = self.admin_client.list_topics(timeout=15)
                    kafka_check = True
                except KafkaException as e:
                    self.logger.error(f"Error while connecting to Kafka: {e}")
                    self.admin_client = None
                    continue
            else:
                self.logger.error(f"Could not find Kafka broker at {self.bootstrap_server}.")
        return kafka_check


    def server_exist(self):

        if ':' not in self.bootstrap_server:
            self.logger.error(f"Error: The boostrap server string {self.bootstrap_server} must be formatted with two integers -> (host:port)")
            return False

        split_values = self.bootstrap_server.split(':')

        if len(split_values) != 2 :
            self.logger.error(f"Error: The boostrap server string {self.bootstrap_server} must be formatted with two integers -> (host:port)")
            return False
            
        host, port = self.bootstrap_server.split(':')

        if not port.isdigit():
            self.logger.error(f"Error: '{port}' is not a valid port number.")
            return False

        try:
            # Attempt to create a socket connection to the Kafka broker
            with socket.create_connection((host, port), timeout=2):
                self.logger.info(f"Server {host}:{port} was reached.")
                return True
        except (socket.error, socket.timeout) as e:
            self.logger.error(f"Server {host}:{port} unreachable: {e}")
            return False

    
    def reset(self):
        self.previous_inbound_traffic_bytes = psutil.net_io_counters().bytes_recv
        self.previous_inbound_traffic_packets = psutil.net_io_counters().packets_recv
        self.previous_inbound_measurement_instant = time.time()
        self.previous_outbound_traffic_bytes = psutil.net_io_counters().bytes_sent
        self.previous_outbound_traffic_packets = psutil.net_io_counters().packets_sent
        self.previous_outbound_measurement_instant = time.time()
        self.health_probes_count = 0


    def stop(self):
        """Signal the monitor to stop immediately. Unblocks any sleeping waits."""
        self._stop_event.set()


    def probe_and_send(self):
        if self._stop_event.is_set():
            return
        self.logger.info(f"HealthMonitor is probing {self.metrics} at {self.topic_name}")
        health_dict = {}

        if CPU in self.metrics:
            health_dict[self.topic_name + "_" + CPU] = self.get_cpu_usage()
            self.logger.debug(f"CPU: {health_dict[self.topic_name + '_' + CPU]}")

        if RAM in self.metrics:
            health_dict[self.topic_name + "_" + RAM] = self.get_memory_usage()
            self.logger.debug(f"Memory: {health_dict[self.topic_name + '_' + RAM]}")

        if RTT in self.metrics:
            health_dict[self.topic_name + "_" + 'external_http_rtt'] = self.get_rtt_requests()
            health_dict.update(self.measure_net_overhead('icmp'))
            health_dict.update(self.measure_net_overhead('http'))

        if INBOUND in self.metrics:
            inbound_traffic_probe = self.get_inbound_traffic()
            health_dict.update(inbound_traffic_probe)
            self.logger.debug(f"Inbound traffic: {inbound_traffic_probe}")

        if OUTBOUND in self.metrics:
            outbound_traffic_probe = self.get_outbound_traffic()
            health_dict.update(outbound_traffic_probe)
            self.logger.debug(f"Outbound traffic: {outbound_traffic_probe}")
            
            
        self.send_health_probes(health_dict)
            

    def send_health_probes(self, data):
        """
        Produce a message to Kafka for a specific sensor type.

        Args:
            data (dict): The data to be sent as a message.
            topic_name (str): The Kafka topic to which the message will be sent.
        """
        try:
            self.producer.produce(topic=self.topic_name, value=data)  # Send the message to Kafka
            self.health_probes_count += 1

            if self.health_probes_count % 10 == 0:
                self.producer.flush(5)
                self.logger.info(f"Tryed flushing {self.health_probes_count} health probes.")
            if self.health_probes_count % 50 == 0:
                self.logger.info(f"sent {self.health_probes_count} health probes for now.")
        except Exception as e:
            print(f"Error while producing message to {self.topic_name} : {e}")


    def release_producer(self):
        if self.producer:
            self.producer.flush(5)
            self.logger.info("Producer thread ended.")


    def get_rtt(self):
            try:
                
                result = subprocess.run(
                    ["ping", "-c", "1", self.ping_host], 
                    capture_output=True, 
                    text=True, 
                    timeout=self.ping_thread_timeout)

                output = result.stdout

                lines = output.split('\n')

                # Estrazone valore latenza dal messaggio di uscita
                for line in lines:
                    if "time=" in line:
                        time_index = line.find("time=")
                        time_str = line[time_index + 5:].split()[0]
                        round_trip_time = float(time_str)
                        break
                

            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error during diagnostics ping request: {e.message}")
                round_trip_time = None

            return round_trip_time


    def get_rtt_curl(self):
            try:
                # Use curl to measure TCP connect time (via proxy if configured)
                result = subprocess.run(
                    [
                        "curl", 
                        "-s",               # Silent mode
                        "-o", "/dev/null",   # Discard output
                        "-w", "%{time_connect}",  # Extract connection time
                        "--http1.1",         # Avoid HTTP/2 multiplexing
                        f"http://{self.ping_host}"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.ping_thread_timeout
                )
                
                # Convert seconds to milliseconds
                round_trip_time = float(result.stdout.strip()) * 1000
                return round_trip_time
            
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error during curl request: {e}")
                return None
        

    def get_rtt_python_sockets(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.ping_thread_timeout)
            start = time.time()
            s.connect((self.ping_host, 80))  # Target port 80
            end = time.time()
            s.close()
            # Convert to milliseconds
            return (end - start) * 1000
        except Exception as e:
            if self.logger:
                self.logger.error(f"TCP connection failed: {e}")
            return None


    def get_rtt_requests(self):
        try:
            start = time.time()
            response = requests.get(f"http://{self.ping_host}", timeout=self.ping_thread_timeout)
            rtt = (time.time() - start) * 1000  # Convert to milliseconds
            return rtt
        except Exception as e:
            if self.logger:
                self.logger.error(f"HTTP request failed: {e}")
            return 900


    def get_cpu_usage(self):
        try:
            cpu_usage = self._psutil_process.cpu_percent(interval=0)
            cpu_usage = (cpu_usage / self.cpu_count) * 100
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during diagnostics cpu usage request: {e.message}")
            cpu_usage = None

        return cpu_usage


    def get_memory_usage(self):
        try:
            memory_usage = psutil.virtual_memory().percent
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during diagnostics memory usage request: {e.message}")
            memory_usage = None

        return memory_usage
    

    def get_inbound_traffic(self):
        try:
            network_stats = psutil.net_io_counters()
            current_measurement_instant = time.time()
            current_inbound_traffic_bytes = network_stats.bytes_recv
            current_inbound_traffic_packets = network_stats.packets_recv


            time_interval = current_measurement_instant - self.previous_inbound_measurement_instant
            inbound_traffic_bytes = current_inbound_traffic_bytes - self.previous_inbound_traffic_bytes
            inbound_traffic_packets = current_inbound_traffic_packets - self.previous_inbound_traffic_packets

            if time_interval > 0:
                inbound_MBps = (inbound_traffic_bytes / time_interval) / (1024 * 1024)
                inbound_packets_per_second = inbound_traffic_packets / time_interval
                inbound_packets_per_second = math.floor(inbound_packets_per_second)
            else:
                inbound_MBps = 0
                inbound_packets_per_second = 0
        
            self.previous_inbound_traffic_bytes = current_inbound_traffic_bytes
            self.previous_inbound_traffic_packets = current_inbound_traffic_packets
            self.previous_inbound_measurement_instant = current_measurement_instant

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during diagnostics inbound traffic volume: {e.message}")
            return None

        return {
            self.topic_name + "_" + "inbound_MBps": inbound_MBps,
            self.topic_name + "_" + "inbound_packets_per_second": inbound_packets_per_second
        }
    

    def get_outbound_traffic(self):
        try:
            network_stats = psutil.net_io_counters()
            current_measurement_instant = time.time()
            current_outbound_traffic_bytes = network_stats.bytes_sent
            current_outbound_traffic_packets = network_stats.packets_sent

            time_interval = current_measurement_instant - self.previous_outbound_measurement_instant
            outbound_traffic_bytes = current_outbound_traffic_bytes - self.previous_outbound_traffic_bytes
            outbound_traffic_packets = current_outbound_traffic_packets - self.previous_outbound_traffic_packets

            if time_interval > 0:
                outbound_traffic_MBps = (outbound_traffic_bytes / time_interval) / (1024 * 1024)
                outbound_packets_per_second = outbound_traffic_packets / time_interval
                outbound_packets_per_second = math.floor(outbound_packets_per_second)
            else:
                outbound_traffic_MBps = 0
                outbound_packets_per_second = 0

            self.previous_outbound_traffic_bytes = current_outbound_traffic_bytes
            self.previous_outbound_traffic_packets = current_outbound_traffic_packets
            self.previous_outbound_measurement_instant = current_measurement_instant

        except Exception as e: 
            if self.logger:
                self.logger.error(f"Error during diagnostics outbound traffic volume: {e.message}")
            return None

        return {
            self.topic_name + "_" + "outbound_MBps": outbound_traffic_MBps,
            self.topic_name + "_" + "outbound_packets_per_second": outbound_packets_per_second
        }


    def measure_net_overhead(self, mode):
        num_requests = self.kwargs.get("rtt_profiling_num_requests")
        interval_ms = self.kwargs.get("rtt_profiling_interval_ms")
        
        target_ip = self.controller_server_url.split(":")[0]

        self.logger.info(f"Measuring overhead ({mode}) to {target_ip} with {num_requests} reqs")
        
        results = {
            self.topic_name + '_' + mode + '_' + "min_rtt_ms": 0.0, 
            self.topic_name + '_' + mode + '_' + "max_rtt_ms": 0.0, 
            self.topic_name + '_' + mode + '_' + "avg_rtt_ms": 0.0, 
            self.topic_name + '_' + mode + '_' + "loss_percent": 0.0}

        if mode == "icmp":
            # Idea 1: High-Frequency ICMP Ping
            interval_sec = interval_ms / 1000.0
            # Note: ping interval < 0.2s requires root privileges in Linux. 
            # Docker usually runs as root, so this should be fine.
            cmd =["ping", "-c", str(num_requests), "-i", str(interval_sec), target_ip]
            
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True)
                output = proc.stdout
                
                # Parse packet loss
                loss_match = re.search(r'(\d+)% packet loss', output)
                if loss_match:
                    results[self.topic_name + '_' + mode + '_' + "loss_percent"] = float(loss_match.group(1))
                
                # Parse min/avg/max
                # Linux ping format: rtt min/avg/max/mdev = 0.045/0.052/0.060/0.005 ms
                rtt_match = re.search(r'min/avg/max/.*? = ([\d\.]+)/([\d\.]+)/([\d\.]+)/', output)
                if rtt_match:
                    results[self.topic_name + '_' + mode + '_' + "min_rtt_ms"] = float(rtt_match.group(1))
                    results[self.topic_name + '_' + mode + '_' + "avg_rtt_ms"] = float(rtt_match.group(2))
                    results[self.topic_name + '_' + mode + '_' + "max_rtt_ms"] = float(rtt_match.group(3))
                    
            except Exception as e:
                self.logger.error(f"ICMP Ping failed: {e}")
                return {"error": str(e)}

        elif mode == "http":
            # Idea 2: Application-Layer HTTP Echo
            rtts =[]
            successful_requests = 0
            url = f"http://{self.controller_server_url}/echo"
            
            for _ in range(num_requests):
                start_time = time.perf_counter()
                try:
                    # 2-second timeout so it doesn't hang forever on dropped packets
                    with urllib.request.urlopen(url, timeout=2) as response:
                        if response.getcode() == 200:
                            successful_requests += 1
                except Exception as e:
                    self.logger.warning(f"HTTP Echo failed: {e}")
                    pass
                
                end_time = time.perf_counter()
                rtt_ms = (end_time - start_time) * 1000.0
                rtts.append(rtt_ms)
                
                if interval_ms > 0:
                    if self._stop_event.wait(interval_ms / 1000.0):
                        break  # stop requested, exit measurement loop early
            
            if rtts:
                results[self.topic_name + '_' + mode + '_' + "min_rtt_ms"] = min(rtts)
                results[self.topic_name + '_' + mode + '_' + "max_rtt_ms"] = max(rtts)
                results[self.topic_name + '_' + mode + '_' + "avg_rtt_ms"] = statistics.mean(rtts)
            
            results[self.topic_name + '_' + mode + '_' + "loss_percent"] = ((num_requests - successful_requests) / num_requests) * 100.0

        self.logger.info(f"Overhead results: {results}")
        return results