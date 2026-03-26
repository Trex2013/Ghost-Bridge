from scapy.all import sniff, IP, DNS, DNSQR
import sys

class spy():
  def __init__(self,target_ip):
    self.target_ip=target_ip.strip()
    print(f"[-] Initialized Spy for: {self.target_ip}")

  def extraction(self,packet):
    if packet.haslayer(IP) and packet[IP].src==self.target_ip:

         if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                 raw_data=packet[DNS].qd.qname
                 site_name=raw_data.decode('utf-8')
                 print(f"[+] Visited: {site_name}")



class main():
    def __init__(self):
     self.spy=None
        
    def run(self):
        
        try:
           target_ip=sys.argv[1]
        except IndexError:
            target_ip=input("[-] No target IP provided. Enter an IP to start monitoring.")   
        self.spy=spy(target_ip)
        sniff(filter="udp port 53", prn=self.spy.extraction , store=False)


if __name__=="__main__":
    main().run()






