from scapy.all import *

def process_packet(packet):
    packetlist=packet.summary().split(" ")
    if packet[IP] != None:                                    #IP is scapy packet obj #name 'ip' is not defined
        srcip=packet[IP].src
        destip=packet[IP].dst
        print("Source IP: ",srcip)
        print("Destination IP: ",destip)

    try:
        if packet[TCP] != None:
            tcp_sport=packet[TCP].sport
            tcp_dport=packet[TCP].dport
            print("Source TCP Port: ",tcp_sport)
            print("Destination TCP Port: ",tcp_dport) #returns 443 if https
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



    layers=packet.layers()              #print the layer names
    layer=[]                            #list that will contained sanitized layer names only from layers list
    for i in layers:
        exp=str(i).replace("'","").replace("<","").replace(">","").replace(" ","")
        try:                #for layer "RAW"
            layer.append(exp.split(".")[3])
        except:
            pass            #I don't want RAW layer

    print(packet.show(dump=True))       #print layer with values
    
    #if packet[IP] != None:
    #    print(packet[IP].version,packet[IP].src)

    hexdump(packet)

    print("==============================================")        
     
capture=sniff(prn=process_packet, store=False)



