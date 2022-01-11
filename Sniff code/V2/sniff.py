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

    #counter=0      #=======================same as show()
    #while True:
    #    if packet.getlayer(counter) == None:
            #break
        #layer=packet.payload
        #print("Layer: ",layer)
        #print(packet.getlayer(counter))
        #counter+=1
    layers=packet.layers()              #print the layer names
    layer=[]
    for i in layers:
        exp=str(i).replace("'","").replace("<","").replace(">","").replace(" ","")
        try:                #for layer "RAW"
            layer.append(exp.split(".")[3])
        except:
            pass
    print(layer)
    print(packet.show(dump=True))       #print layer with values
    #print("\n\n\nLayers: \n",packet.payload.layers())
    if packet[IP] != None:
        print(packet[IP].version,packet[IP].src)
    print("==============================================")        
    #Layers:  [<class 'scapy.layers.inet.IP'>, <class 'scapy.layers.inet.TCP'>, <class 'scapy.packet.Raw'>]
    #[<class 'scapy.layers.inet.IP'>, <class 'scapy.layers.inet.UDP'>, <class 'scapy.packet.Raw'>]    
capture=sniff(prn=process_packet, store=False)



