import scapy.all as scapy

def process_packet(packet):
    original=packet.summary()
    packet=original.split(" ")
    try:
        p=packet.index("TCP")
        #print(" ".join(packet))
        if IP in original:
            print(original.src)
    except:
        print("\n",original)
        
capture=scapy.sniff(prn=process_packet, store=False)



