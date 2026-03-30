import multiprocessing
import sys
import logging
from scapy.all import sniff, IP, DNS, DNSQR, TCP, UDP, load_layer, Ether
from scapy.layers.http import HTTPRequest 
load_layer("tls")
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from logger import start_logger_process 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class mmdb():
    def __init__(self):
       
        try:
            import geoip2.database
            self.file = geoip2.database.Reader('GeoLite2-ASN.mmdb')
        except:
            self.file = None

    def read(self, ip):
        if not self.file: return None
        try: 
            results = self.file.asn(ip)
            return results.autonomous_system_organization
        except:
            return None        

class Spy():
    def __init__(self, target_ip, queue):
        self.target_ip = target_ip.strip()
        self.queue = queue
        self.reader = mmdb()
        self.ip_cache = {}

    def extraction(self, packet):
        if not packet.haslayer(IP) or packet[IP].src != self.target_ip:
            return
        
        
        src_mac = packet[Ether].src if packet.haslayer(Ether) else None
        dst_mac = packet[Ether].dst if packet.haslayer(Ether) else None
        sport, dport, tcp_flags, tcp_window = None, None, None, None
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)
            tcp_window = packet[TCP].window
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
         
        payload_size = len(packet[IP].payload) if packet.haslayer(IP) else 0   
        data = {
            "timestamp": packet.time,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": self.target_ip,
            "dst_ip": packet[IP].dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": None,               
            "metadata": None,               
            "packet_size": len(packet),
            "payload_size": payload_size,
            "ttl": packet[IP].ttl,
            "ip_id": packet[IP].id,         
            "ip_flags": str(packet[IP].flags), 
            "tcp_flags": tcp_flags,         
            "tcp_window": tcp_window        
        }
        # data = {"timestamp": packet.time, "src_ip": self.target_ip, "dst_ip": packet[IP].dst,  "protocol": None, "metadata": None, "packet size": f"{len(packet)} bytes",   "payload size": f"{len(packet[IP].payload)} bytes", "ttl": packet[IP].ttl, "flags": packet[IP].flags, "options": packet[IP].options, "payload options": packet[IP].payload.options ,"src port": packet[IP].sport, "dst port": packet[IP].dport, "src_mac": packet[IP].src_mac, "dst_mac": packet[IP].dst_mac} # Added packet size, TTL, and flags for more context

        # DNS
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            data["protocol"] = "DNS"
            data["metadata"] = packet[DNS].qd.qname.decode('utf-8', errors='ignore')

        # HTTP
        elif packet.haslayer(HTTPRequest):
            try:
                data["protocol"] = "HTTP"
                data["metadata"] = packet[HTTPRequest].Host.decode('utf-8', errors='ignore')
            except: pass

        #TLS/HTTPS 
        elif packet.haslayer(TLSClientHello) and packet.haslayer(TLS_Ext_ServerName):
            try:
                data["protocol"] = "TLS-SNI"
                data["metadata"] = packet[TLS_Ext_ServerName].servernames[0].servername.decode('utf-8')
            except: pass

        # QUIC/UDP 443 
        elif packet.haslayer(UDP) and packet[UDP].dport == 443:
            raw_IP = packet[IP].dst
            if raw_IP not in self.ip_cache:
                org = self.reader.read(raw_IP)
                self.ip_cache[raw_IP] = org if org else raw_IP
            
            data["protocol"] = "QUIC"
            data["metadata"] = self.ip_cache[raw_IP]

        if data["protocol"]:
            self.queue.put(data)

class GhostBridgeApp():
    def __init__(self):
        self.data_queue = multiprocessing.Queue()

    def run(self):
        try:
            target_ip = sys.argv[1]
        except IndexError:
            target_ip = input("[-] No target IP provided. Enter an IP: ")

       
        log_proc = multiprocessing.Process(target=start_logger_process, args=(self.data_queue,))
        log_proc.daemon = True 
        log_proc.start()

        
        spy_engine = Spy(target_ip, self.data_queue)
        print(f"[*] Ghost Bridge active on {target_ip}. Logging to CSV...")
        
        try:
            sniff(filter=f"ip src {target_ip} and (udp port 53 or tcp port 443 or udp port 443 or tcp port 80)", 
                  prn=spy_engine.extraction, store=False)
        except KeyboardInterrupt:
            print("\n[!] Shutting down framework...")
            self.data_queue.put("STOP")
            log_proc.join(timeout=2)
            sys.exit(0)

if __name__ == "__main__":
    GhostBridgeApp().run()