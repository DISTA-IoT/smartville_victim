import time
import psutil
import subprocess
import math
import socket
import requests
from confluent_kafka.admin import AdminClient, NewTopic
from confluent_kafka import KafkaException
from confluent_kafka import Producer, SerializingProducer
from confluent_kafka.serialization import StringSerializer
import json

CPU = "CPU"
RAM = "RAM"
RTT = "RTT"
INBOUND = "INBOUND"
OUTBOUND = "OUTBOUND"
HEALTH = "HEALTH"

        
class HealthMonitor():


    def __init__(self, kwargs):
        self.topic_name = kwargs['host_ip']
        self.logger = kwargs['logger']
        self.ping_thread_timeout = kwargs['ping_thread_timeout']
        self.ping_host = kwargs['ping_host']
        self.probe_frequency_seconds = kwargs['probe_frequency_seconds']
        self.stopme = False
        self.metrics = kwargs['probe_metrics']
        self.bootstrap_server = kwargs['bootstrap_server']
        self.max_conn_retries = kwargs['max_conn_retries']
        self.other_configs = kwargs
        self.alive = False
        self.conf_prod = {
            'bootstrap.servers': self.bootstrap_server,
            'key.serializer': StringSerializer('utf_8'),
            'value.serializer': lambda x, ctx: json.dumps(x).encode('utf-8')
            }
        if self.check_kafka_server():
            if self.create_topic():
                self.producer = SerializingProducer(self.conf_prod)
                self.alive = True
                self.logger.info(f"Node HealthMonitor initialized. Will probe {self.metrics} every {self.probe_frequency_seconds} seconds.")
                self.reset()
                

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
        self.previous_inbound_traffic = psutil.net_io_counters().bytes_recv
        self.previous_inbound_measurement_instant = time.time()
        self.previous_outbound_traffic = psutil.net_io_counters().bytes_sent
        self.previous_outbound_measurement_instant = time.time()
        self.health_probes_count = 0


    def probe_and_send(self):

        health_dict = {}

        if CPU in self.metrics:
            health_dict[self.topic_name + "_" + CPU] = self.get_cpu_usage()
            self.logger.debug(f"CPU: {health_dict[self.topic_name + '_' + CPU]}")

        if RAM in self.metrics:
            health_dict[self.topic_name + "_" + RAM] = self.get_memory_usage()
            self.logger.debug(f"Memory: {health_dict[self.topic_name + '_' + RAM]}")

        if RTT in self.metrics:
            health_dict[self.topic_name + "_" + RTT] = self.get_rtt_requests()
            self.logger.debug(f"RTT: {health_dict[self.topic_name + '_' + RTT]}")

        if INBOUND in self.metrics:
            health_dict[self.topic_name + "_" + INBOUND] = self.get_inbound_traffic()
            self.logger.debug(f"Inbound traffic: {health_dict[self.topic_name + '_' + INBOUND]}")

        if OUTBOUND in self.metrics:
            health_dict[self.topic_name + "_" + OUTBOUND] = self.get_outbound_traffic()
            self.logger.debug(f"Outbound traffic: {health_dict[self.topic_name + '_' + OUTBOUND]}")
            
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
                self.producer.flush()
            if self.health_probes_count % 50 == 0:
                self.logger.info(f"sent {self.health_probes_count} health probes for now.")
        except Exception as e:
            print(f"Error while producing message to {self.topic_name} : {e}")


    def release_producer(self):
        if self.producer:
            self.producer.close()
            self.logger.info("Producer closed.")


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