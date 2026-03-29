from scapy.all import sniff, IP, DNS, DNSQR, TCP, UDP, load_layer
import sys
from scapy.layers.http import HTTPRequest 
load_layer("tls")
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName
import logging
import geoip2.database

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

ip_cache = {}
class mmdb():
    def __init__ (self):
        pass
    
    def read (self, ip):
       try: 
           with geoip2.database.Reader('GeoLite2-ASN.mmdb') as file:
               results = file.asn(ip)
               return results.autonomous_system_organization
           
       except Exception as e:
           return None    
class spy():
  def __init__(self,target_ip):
    self.target_ip=target_ip.strip()
    print(f"[-] Initialized Spy for: {self.target_ip}")
    self.reader=mmdb()

  def extraction(self,packet):
    if packet.haslayer(IP) and packet[IP].src==self.target_ip:

         if packet.haslayer(DNS) and packet.haslayer(DNSQR): #udp 53 dnsq
                 raw_data=packet[DNS].qd.qname
                 site_name=raw_data.decode('utf-8')
                 print(f"[+] (DNS) Visited: {site_name}")
                 
         elif packet.haslayer(HTTPRequest): #tcp 80 http
             try:   
                 raw_data=packet[HTTPRequest].Host
                 clean_data=raw_data.decode('utf-8')
                 print(f"[+] (HTTP) Visited: {clean_data}")
             except:
                 pass    
                 
         elif packet.haslayer(TLSClientHello) and packet.haslayer(TLS_Ext_ServerName): #tcp 443 tls
             try:
                 raw_data=packet[TLS_Ext_ServerName].servernames[0].servername
                 clean_data=raw_data.decode('utf-8')
                 print(f"[+] (TLS-SNI Handshake) Visited: {clean_data}")   
             except:
                 pass
             
         elif packet.haslayer(UDP) and packet[UDP].dport==443: #udp 443 quic
                    try:
                        raw_IP=packet[IP].dst
                        if raw_IP not in ip_cache:
                            org_name=self.reader.read(raw_IP)
                            ip_cache[raw_IP]=org_name
                            clean_data=org_name if org_name else raw_IP
                            
                        else:
                            clean_data=ip_cache[raw_IP]
                            
                        print(f"[+] (QUIC-High speed Streaming) Visited: {clean_data}")
                    except:
                        pass



class main():
    def __init__(self):
     self.spy=None
        
    def run(self):
        
        try:
           target_ip=sys.argv[1]
        except IndexError:
            target_ip=input("[-] No target IP provided. Enter an IP to start monitoring:")   
        self.spy=spy(target_ip)
        sniff(filter="udp port 53 or tcp port 443 or tcp port 80 or udp port 443", prn=self.spy.extraction , store=False)


if __name__=="__main__":
    main().run()






