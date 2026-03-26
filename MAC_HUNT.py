import sys
from scapy.all import ARP, Ether, srp, conf
import csv

class local_prep():
    def __init__ (self):
        pass
    
    def default_gate(self):
        
        local_arpt = conf.route.route("0.0.0.0") #to local machine
        gateway_ip = local_arpt[2]
        return gateway_ip
    
    def subnet(self):
        ip_parts = self.default_gate().split('.')
        cdir = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24" #create broadcast ip
        return cdir
    
    def mac_oui(self,mac):
        mac_parts=mac.split(':')
        mac_oui_part=f"{mac_parts[0]}{mac_parts[1]}{mac_parts[2]}"
        mac_second_bit = mac_parts[0][1]
        
        
        return mac_oui_part , mac_second_bit
    
    def mac_man_search(self,oui_dict,mac_oui_part,mac_second_bit):
        if mac_second_bit in ["2","6","a","e"]:
                manufacturer = "Randomly Generated MAC Address"
                return manufacturer
        else: 
            manufacturer = oui_dict.get(mac_oui_part.lower(), "Unknown Not Found") #get used to locate the value assigned with "Assignment" key in the dict, else ---> not found
        
            
        return manufacturer          
                
                

        
    def scan_network(self):
        book = []
        arp_req = ARP(pdst=self.subnet()) #creates arp packet
        ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff") 
        
        packet = ethernet_frame/arp_req
        answered_list = srp(packet,timeout=1,verbose=False)[0]  #fired through the local network for all devices with broadcast ip and mac
        
        with open ("oui.csv" , "r", encoding="utf-8") as oui:
            
            oui__reader = csv.DictReader(oui)
            oui_dict ={}
            
            for row in oui__reader: #creating a dict bcs csv dict  is one way 
                oui_dict[row["Assignment"].lower()] = row["Organization Name"] 
            
            # print(oui_dict)              
            
            
            for i, element in enumerate(answered_list, 1):
                cilent_ip = element[1].psrc  #packet source ip
                client_mac = element[1].hwsrc #packet source mac
                
                mac_oui_part,mac_second_bit=self.mac_oui(client_mac)
                
                manufacturer = self.mac_man_search(oui_dict,mac_oui_part,mac_second_bit)
                
                print(f"{i}. IP: {cilent_ip}  ====>  MAC: {client_mac}  ====>  Manufacturer: {manufacturer}")
                book.append({'ip':cilent_ip,'mac':client_mac,'manufacturer':manufacturer})
                
               
                
            
        if not book:
            print("No devices found on the network or connection error.")
            return None,None,None,None
        
        target=int(input("\n[#] Scan complete. Please select a target from the list above: "))
        target_ip = book[target-1]['ip']
        target_mac = book[target-1]['mac']
        
        #to get the gateway mac
        gateway_ip = self.default_gate() #get thje gateway ip 
        gateway_mac = None
        for entry in book:
            if entry['ip']==gateway_ip: #if gateway ip found on the book , pull out the mac from that entry
                gateway_mac=entry['mac']
                break
        
        if gateway_mac is None:
            print("Gateway MAC address not found in the scan results.")
            sys.exit(1)
            
        return target_ip, target_mac, gateway_ip, gateway_mac