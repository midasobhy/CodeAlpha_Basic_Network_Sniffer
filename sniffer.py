from scapy.all import sniff
from scapy.layer.inet import IP, TCP, UDP 

def packet_handler(packet):
    
    if packet.haslayer(IP):
       
        ip_layer = packet.getlayer(IP)
          print (f"IP Packet: {ip_layer.scr}- > {ip_layer.dst}")



     if packet.haslayer(TCP):

        tcp_layer = packer.getlayer(TCP)
 
        print (f"TCP Segment: Port { tcp_layer.sport} - > {tcp_layer.dport}")

    elif packet.haslayer(UDP):
         udp_layer = packet.getlayer(UDP)
         print (f"UDP Datagram: Port {udp_layer.sport} - >{udp_layer.dport}")

def start_sniffing():
         print ("starting network sniffing ..."
         sniff(prn=packet_handler, store=0)

if ___name__= = "__mian__":
      
     start_sniffing()


 
