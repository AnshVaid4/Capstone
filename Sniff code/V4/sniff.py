from scapy.all import *
from ipaddress import *
from datetime import datetime
import base64
import os

monsrcip=input("Enter the IP you want to monitor: ")
monsrcport=input("Enter the source port you want to monitor: ")
monhostport=input("Enter the port of your device you want to monitor: ")

if monsrcip == "":
    print("[-] IP address cannot be blank")
    quit()
    
if monsrcport == "":
    monsrcport="N"
    
if monhostport == "":
    monhostport="N"

logpacket="n"

if monsrcip != "N":
    ipobj = IPv4Network(monsrcip)
    dt=datetime.now()

def process_packet(packet):
    global logpacket
    srcip=None
    destip=None
    srcport=None
    destport=None

    packetlen=None
    packetttl=None
    protocol=None

    flags=None

    date=None
    time=None

    b64enc=None
    print("[+]",packet.summary())
    
    if packet.haslayer(IP) and packet[IP] != None:  #IP is scapy packet obj #name 'ip' is not defined
        srcip=packet[IP].src
        destip=packet[IP].dst                       #protocol=packet[IP].proto
        packetlen=packet[IP].len
        packetttl=packet[IP].ttl
        if monsrcip != "N" and ((IPv4Address(srcip) in ipobj) or (IPv4Address(destip) in ipobj)):
            print("[-]Logged| Source IP: ",srcip," Destination IP: ",destip)
            logpacket="y"

        
    if packet.haslayer(ARP) and packet[ARP] != None:
       srcip=packet[ARP].psrc
       destip=packet[ARP].pdst
       if monsrcip != "N" and ((IPv4Address(srcip) in ipobj) or (IPv4Address(destip) in ipobj)):
            print("[-]Logged| Source IP: ",srcip," Destination IP: ",destip)
            logpacket="y"
       
    
    if packet.haslayer(TCP) and packet[TCP] != None:
        srcport=packet[TCP].sport
        destport=packet[TCP].dport
        protocol="TCP"
        flags=packet[TCP].flags
        if monsrcport != "N" and monsrcport == srcport:
            print("[-]Logged| Source port: ",srcport," Destination port: ",destport)
            logpacket="y"
        if monhostport != "N" and monhostport == destport:
            print("[-]Logged| Destination port: ",destport," Source port: ",srcport)
            logpacket="y"
                                                                    #returns 443 if https
    if packet.haslayer(UDP) and packet[UDP] != None:                                          #IndexError: Layer [UDP] not found
        srcport=packet[UDP].sport
        destport=packet[UDP].dport
        protocol="UDP"
        if monsrcport != "N" and monsrcport == srcport:
            print("[-]Logged| Source port: ",srcport," Destination port: ",destport)
            logpacket="y"
        if monhostport != "N" and monhostport == destport:
            print("[-]Logged| Destination port: ",destport," Source port: ",srcport)
            logpacket="y"



    if logpacket == "y":
        datetime=dt.strftime("%d/%m/%Y %H:%M:%S")
        datetime=datetime.split(" ")
        date=datetime[0]
        time=datetime[1]
        
        dump=str(hexdump(packet))
        dump=dump.encode("ascii")
        b64enc=base64.b64encode(dump)

        print("Source IP: ",srcip," Destination IP: ",destip,"\nSource port: ",srcport," Destination port: ",destport,"\nPacket length: ",packetlen," Packet TTL ",packetttl,
              "\nProtocol: ",protocol," Flags ",flags,"\nDate: ",date," Time: ",time,"\n\nBase64 encoded RAW\n",b64enc)
        logpacket="n"
    print("===========================================================================")        
     
capture=sniff(prn=process_packet, store=False)



