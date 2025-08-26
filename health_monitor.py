import time
import psutil
import subprocess
import math
import socket
import requests
from confluent_kafka.admin import AdminClient
from confluent_kafka import KafkaException

CPU = "CPU"
RAM = "RAM"
RTT = "RTT"
INBOUND = "INBOUND"
OUTBOUND = "OUTBOUND"
HEALTH = "HEALTH"


def server_exist(bootstrap_servers):

    # Controlla se la stinga è del formato host:porta

    if ':' not in bootstrap_servers:
        print(f"Error: The boostrap server string {bootstrap_servers} must be formatted with two integers -> (host:port)")
        return False

    split_values = bootstrap_servers.split(':')

    if len(split_values) != 2 :
        print(f"Error: The boostrap server string {bootstrap_servers} must be formatted with two integers -> (host:port)")
        return False
        
    host, port = bootstrap_servers.split(':')

    if not port.isdigit():
        print(f"Error: '{port}' is not a valid port number.")
        return False

    try:
        # Attempt to create a socket connection to the Kafka broker
        with socket.create_connection((host, port), timeout=2):
            print(f"Server {host}:{port} was reached.")
            return True
    except (socket.error, socket.timeout) as e:
        print(f"Server {host}:{port} unreachable")
        return False


class HealthMonitor():


    def __init__(self, kwargs):
        self.host_ip = kwargs['host_ip']
        self.logger = kwargs['logger']
        self.ping_thread_timeout = kwargs['ping_thread_timeout']
        self.ping_host = kwargs['ping_host']
        self.probe_frequency_seconds = kwargs['probe_frequency_seconds']
        self.stopme = False
        self.metrics = kwargs['probe_metrics']
        self.logger.info(f"Node HealthMonitor initialized. Will probe {self.metrics} every {self.probe_frequency_seconds} seconds.")
        self.reset()

        kafka_check = False

        while not kafka_check:

            bootstrap_servers = '192.168.1.1:9092'

            if server_exist(bootstrap_servers):
                try:
                    #consumer_conf = {'bootstrap.servers': bootstrap_servers, 'group.id': 'my-group'}
                    conf = {'bootstrap.servers': bootstrap_servers}
                    #consumer = Consumer(consumer_conf)
                    admin = AdminClient(conf)

                    topics = admin.list_topics(timeout=15)

                    kafka_check = True

                except KafkaException as e:
                    print(f"Connection Error")
                    admin = None
                    continue
            else:
                print(f"Could not find Kafka broker at {bootstrap_servers}.")

    
    
    def reset(self):
        self.previous_inbound_traffic = psutil.net_io_counters().bytes_recv
        self.previous_inbound_measurement_instant = time.time()
        self.previous_outbound_traffic = psutil.net_io_counters().bytes_sent
        self.previous_outbound_measurement_instant = time.time()


    def probe_health(self):

        health_dict = {}

        if CPU in self.metrics:
            health_dict[self.host_ip + "_" + CPU] = self.get_cpu_usage()
            self.logger.debug(f"CPU: {health_dict[self.host_ip + '_' + CPU]}")

        if RAM in self.metrics:
            health_dict[self.host_ip + "_" + RAM] = self.get_memory_usage()
            self.logger.debug(f"Memory: {health_dict[self.host_ip + '_' + RAM]}")

        if RTT in self.metrics:
            health_dict[self.host_ip + "_" + RTT] = self.get_rtt_requests()
            self.logger.debug(f"RTT: {health_dict[self.host_ip + '_' + RTT]}")

        if INBOUND in self.metrics:
            health_dict[self.host_ip + "_" + INBOUND] = self.get_inbound_traffic()
            self.logger.debug(f"Inbound traffic: {health_dict[self.host_ip + '_' + INBOUND]}")

        if OUTBOUND in self.metrics:
            health_dict[self.host_ip + "_" + OUTBOUND] = self.get_outbound_traffic()
            self.logger.debug(f"Outbound traffic: {health_dict[self.host_ip + '_' + OUTBOUND]}")
            
        return health_dict
            

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
            cpu_usage =  psutil.cpu_percent(interval=1)
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
            current_inbound_traffic = network_stats.bytes_recv

            time_interval = current_measurement_instant - self.previous_inbound_measurement_instant
            inbound_traffic = current_inbound_traffic - self.previous_inbound_traffic

            if time_interval > 0:
                inbound_traffic_per_second = inbound_traffic / time_interval
                inbound_traffic_per_second = math.floor(inbound_traffic_per_second)
            else:
                inbound_traffic_per_second = 0
        
            self.previous_inbound_traffic = current_inbound_traffic
            self.previous_inbound_measurement_instant = current_measurement_instant

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during diagnostics inbound traffic volume: {e.message}")
            return None

        return inbound_traffic_per_second
    

    def get_outbound_traffic(self):
        try:
            network_stats = psutil.net_io_counters()
            current_measurement_instant = time.time()
            current_outbound_traffic = network_stats.bytes_sent

            time_interval = current_measurement_instant - self.previous_outbound_measurement_instant
            outbound_traffic = current_outbound_traffic - self.previous_outbound_traffic

            if time_interval > 0:
                outbound_traffic_per_second = outbound_traffic / time_interval
                outbound_traffic_per_second = math.floor(outbound_traffic_per_second)
            else:
                outbound_traffic_per_second = 0

            self.previous_outbound_traffic = current_outbound_traffic
            self.previous_outbound_measurement_instant = current_measurement_instant

        except Exception as e: 
            if self.logger:
                self.logger.error(f"Error during diagnostics outbound traffic volume: {e.message}")
            return None

        return outbound_traffic_per_second