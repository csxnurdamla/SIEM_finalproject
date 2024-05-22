import csv
from datetime import datetime
from scapy.all import *

def get_protocol(pkt):
    if IP in pkt:
        if TCP in pkt:
            return "TCP"
        elif UDP in pkt:
            return "UDP"
        else:
            return "Unknown"
    else:
        return "Unknown"

def parse_modbus(pkt):
    modbus_function = "N/A"
    modbus_data = "N/A"
    modbus_message_address = "N/A"
    modbus_error_control = "N/A"
    packet_payload = "N/A"
    
    if Raw in pkt and TCP in pkt:
        payload = pkt[Raw].load
        packet_payload = payload.hex()
        
        if len(payload) > 7:
            modbus_function = payload[7]
            modbus_data = payload[8:].hex()
            modbus_message_address = int.from_bytes(payload[8:10], byteorder='big')
            modbus_error_control = payload[-2:].hex()
    
    return modbus_function, modbus_data, modbus_message_address, modbus_error_control, packet_payload

def packet_handler(pkt):
    dest_mac = src_mac = ether_type = src_ip = dst_ip = src_port = dst_port = length = ttl = protocol = "N/A"
    
    if Ether in pkt:  
        dest_mac = pkt[Ether].dst  
        src_mac = pkt[Ether].src   

        if Ether in pkt:
            ether_type = hex(pkt[Ether].type)
        
        if IP in pkt: 
            ttl = pkt[IP].ttl
            length = pkt[IP].len
            src_ip = pkt[IP].src  
            dst_ip = pkt[IP].dst 
            
            if TCP in pkt:  
                src_port = pkt[TCP].sport  
                dst_port = pkt[TCP].dport  
                protocol = "TCP"
            elif UDP in pkt:  
                src_port = pkt[UDP].sport  
                dst_port = pkt[UDP].dport  
                protocol = "UDP"

    timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
    modbus_function, modbus_data, modbus_message_address, modbus_error_control, packet_payload = parse_modbus(pkt)

    packet_data = [src_mac, dest_mac, ether_type, src_ip, dst_ip, length, ttl, src_port, dst_port, protocol, timestamp, modbus_function, modbus_data, modbus_message_address, modbus_error_control, packet_payload]
    
    with open('packet_data.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(packet_data)

with open('packet_data.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Source MAC", "Destination MAC", "EtherType", "Source IP", "Destination IP", "Length", "TTL", "Source Port", "Destination Port", "Protocol", "Timestamp", "Modbus Function", "Modbus Data", "Modbus Message Address", "Modbus Error Control", "Packet Payload"])


sniff(prn=packet_handler, count=10)  
