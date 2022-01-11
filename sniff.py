from scapy.all import *

def process_packet(packet):
    packetlist=packet.summary().split(" ")
    if IP in packet:                                    #IP is scapy packet obj #name 'ip' is not defined
        ip_src=packet[IP].src
        print("Source IP: ",ip_src)

    try:
        if TCP in packet:
            tcp_sport=packet[TCP].sport
            print("Source TCP Port: ",tcp_sport)
        else:                                           #IndexError: Layer [UDP] not found
            udp_sport=packet[UDP].sport
            print("Source UDP Port: ",udp_sport)
    except:
        None
    
    try:
        if packetlist.index("TCP"):
            print("TCP: ",packet.summary())
    except:
        print("UDP: ",packet.summary())
    
        
capture=sniff(prn=process_packet, store=False)



