import csv
import os
from datetime import datetime
import time

class GhostLog:
    def __init__(self):
        self.log_dir = "logs"
        os.makedirs(self.log_dir, exist_ok=True)
        self.fields = ["timestamp","src_mac","dst_mac","src_ip","dst_ip","src_port","dst_port","protocol","metadata","packet_size","payload_size","ttl","ip_id","ip_flags","tcp_flags","tcp_window"]
        self.current_log_file = None
        self.end_time = 0
        self._rotate_file() 
    def _rotate_file(self):
        """Internal helper to create a new file every hour."""
        log_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_log_file = os.path.join(self.log_dir, f"ghost_log_{log_time}.csv")
        self.end_time = time.time() + 3600  
        
        with open(self.current_log_file, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.fields)
            writer.writeheader()
        print(f"[!] New Log Created: {self.current_log_file}")

    def log(self, data):


        if time.time() > self.end_time:
            self._rotate_file()

        try:
            with open(self.current_log_file, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.fields)
                writer.writerow({
                    "timestamp": data.get("timestamp"),
                    "src_mac": data.get("src_mac"),
                    "dst_mac": data.get("dst_mac"),
                    "src_ip": data.get("src_ip"),
                    "dst_ip": data.get("dst_ip"),
                    "src_port": data.get("src_port"),
                    "dst_port": data.get("dst_port"),
                    "protocol": data.get("protocol"),               
                    "metadata": data.get("metadata"),               
                    "packet_size": data.get("packet_size"),
                    "payload_size": data.get("payload_size"),
                    "ttl": data.get("ttl"),
                    "ip_id": data.get("ip_id"),
                    "ip_flags": data.get("ip_flags"),
                    "tcp_flags": data.get("tcp_flags"),
                    "tcp_window": data.get("tcp_window")       
                })
        except Exception as e:
            print(f"[!] Logging Error: {e}")


def start_logger_process(queue):

    logger = GhostLog()
    while True:
        packet_data = queue.get()
        if packet_data == "STOP":
            print("[!] Logger shutting down.")
            break
        logger.log(packet_data)