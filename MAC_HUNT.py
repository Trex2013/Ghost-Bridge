from scapy.all import ARP, Ether, srp, conf

class local_prep:
    def __init__ (self):
        pass
    
    def default_gate(self):
        local_arpt = conf.route.route("0.0.0.0")
        gateway_ip = local_arpt[2]
        return gateway_ip
    
    def subnet(self):
        ip_parts = self.default_gate().split('.')
        cdir = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        return cdir
    
    def scan_network(self):
        book = []
        arp_req = ARP(pdst=self.subnet())
        ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        
        packet = ethernet_frame/arp_req
        answered_list = srp(packet,timeout=1,verbose=False)[0]

        for i, element in enumerate(answered_list, 1):
            cilent_ip=element[1].psrc
            client_mac=element[1].hwsrc
            
            print(f"{i}. IP: {cilent_ip}  ====>  MAC: {client_mac}")
            book.append({'ip':cilent_ip,'mac':client_mac})
            
        if not book:
            print("No devices found on the network or connection error.")
            return None,None,None,None
        
        target=int(input("\n[#] Scan complete. Please select a target from the list above: "))
        target_ip = book[target-1]['ip']
        target_mac = book[target-1]['mac']
        gateway_ip = self.default_gate()
        
        for entry in book:
            if entry['ip']==gateway_ip:
                gateway_mac=entry['mac']
                break
            
        return target_ip, target_mac, gateway_ip, gateway_mac