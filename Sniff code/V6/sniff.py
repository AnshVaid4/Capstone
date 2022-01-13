from scapy.all import *
from ipaddress import *
import mysql.connector
from csv import DictWriter

con = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  database="capstone"
)

monsrcip=input("Enter the IP you want to monitor: ")
monsrcport=input("Enter the source port you want to monitor: ")
monhostport=input("Enter the port of your device you want to monitor: ")

if monsrcip == "":
    print("[-] IP address cannot be blank")
    quit()
    
if monsrcport == "":
    monsrcport="N"
else:
    monsrcport=int(monsrcport)
    
if monhostport == "":
    monhostport="N"
else:
    monhostport=int(monhostport)

logpacket="n"
flag=0

if monsrcip != "N":
    ipobj = IPv4Network(monsrcip)

totalpackets=0
defaulterpackets=0

def process_packet(packet):
    from datetime import datetime
    global logpacket
    global totalpackets
    global defaulterpackets
    global flag
    totalpackets+=1
    
    srcip=None
    destip=None
    srcport=None
    destport=None

    packetlen=None
    packetttl=None
    protocol=None
    os=None
    
    flags="NULL"

    date=None
    time=None

    dt=datetime.now()
    datetime=dt.strftime("%Y/%m/%d %H:%M:%S")
    datetime=datetime.split(" ")
    date=datetime[0]
    time=datetime[1]
    datef=dt.strftime("%Y-%m-%d")

    #===========================================================================================================MAIN OPERATIONS
    
    print("[+]",packet.summary())
    
    if packet.haslayer(IP) and packet[IP] != None:  #IP is scapy packet obj #name 'ip' is not defined
        srcip=packet[IP].src
        destip=packet[IP].dst                       #protocol=packet[IP].proto
        packetlen=packet[IP].len
        packetttl=packet[IP].ttl
        if packetttl == 128:
            os="W"
        elif packetttl == 64:
            os="L"
        elif packetttl == 60:
            os="M"
        else:
            os="O"
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
        flags=str(packet[TCP].flags)
        if (monsrcport != "N") and (monsrcport == srcport):
            print("[-]Logged| Source port: ",srcport," Destination port: ",destport)
            logpacket="y"
        if (monhostport != "N") and (monhostport == destport):
            print("[-]Logged| Destination port: ",destport," Source port: ",srcport)
            logpacket="y"
                                                                    #returns 443 if https
    if packet.haslayer(UDP) and packet[UDP] != None:                                          #IndexError: Layer [UDP] not found
        srcport=packet[UDP].sport
        destport=packet[UDP].dport
        protocol="UDP"
        if (monsrcport != "N") and (monsrcport == srcport):
            print("[-]Logged| Source port: ",srcport," Destination port: ",destport)
            logpacket="y"
        if (monhostport != "N") and ((monhostport == srcport) or (monhostport == destport)):
            print("[-]Logged| Destination port: ",destport," Source port: ",srcport)
            logpacket="y"

    #===========================================================================================================IF DEFAULTER

    if logpacket == "y":
        defaulterpackets+=1
        
        hexdump(packet)

        print("\n\nSource IP: ",srcip," Destination IP: ",destip,"\nSource port: ",srcport," Destination port: ",destport,"\nPacket length: ",packetlen," Packet TTL: ",packetttl," OS: ",os,
              "\nProtocol: ",protocol," Flags: ", flags,"\nDate: ",date," Time: ",time)

        insQuery= ("insert into packet"
        "(id, sourceip, destinationip, sourceport, destinationport, packetlength, packetttl, os, protocol, flags, date, time)"
        "VALUES ('NULL', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")

        dataQuery = (srcip, destip, srcport, destport, packetlen, packetttl, os, protocol, flags, date, time)

        cursor = con.cursor()
        cursor.execute(insQuery, dataQuery)
        con.commit()

        logpacket="n"

    #===========================================================================================================FILE OPERATIONS

    pkt=(defaulterpackets, totalpackets,protocol,packetttl,packetlen, date, time)
    with open(f"{datef}.csv", "a") as file:
        if flag == 0:
            headers = ["Defaulter", "Total","Protocol","TTL","Length", "Date", "Time"]
            csv_writer = DictWriter(file, fieldnames=headers)
            csv_writer.writeheader()
            flag=1
        headers = ["Defaulter", "Total","Protocol","TTL","Length", "Date", "Time"]
        csv_writer = DictWriter(file, fieldnames=headers)
        csv_writer.writerow({"Defaulter": pkt[0], "Total": pkt[1], "Protocol": pkt[2], "TTL": pkt[3], "Length": pkt[4], "Date": pkt[5], "Time": pkt[6]})
    
    print("===========================================================================")        
     
capture=sniff(prn=process_packet, store=False)



