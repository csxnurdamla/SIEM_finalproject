import os
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

def packet_handler(pkt, writer):
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
    
    writer.writerow(packet_data)

def packet_handler_from_csv(source_file, destination_file):
    with open(source_file, mode='r', newline='') as source, open(destination_file, mode='w', newline='') as destination:
        reader = csv.DictReader(source)
        writer = csv.writer(destination)
        
        # Yazılacak başlıkları yaz
        writer.writerow(["Source MAC", "Destination MAC", "EtherType", "Source IP", "Destination IP", "Length", "TTL", "Source Port", "Destination Port", "Protocol", "Timestamp", "Modbus Function", "Modbus Data", "Modbus Message Address", "Modbus Error Control", "Packet Payload"])

        for row in reader:
            packet_data = [
                row["src"],  # Source MAC
                row["dst"],  # Destination MAC
                "",  # EtherType
                row["src"],  # Source IP
                row["dst"],  # Destination IP
                "",  # Length
                "",  # TTL
                row["s_port"],  # Source Port
                row["Tag"],  # Destination Port
                row["proto"],  # Protocol
                "",  # Timestamp
                row["Modbus_Function_Code"],  # Modbus Function
                row["Modbus_Value"],  # Modbus Data
                row["Modbus_Transaction_ID"],  # Modbus Message Address
                "",  # Modbus Error Control
                row["Modbus_Function_Description"]  # Packet Payload
            ]
            writer.writerow(packet_data)

def packet_handler_from_live_capture(destination_file):
    destination_headers = ["Source MAC", "Destination MAC", "EtherType", "Source IP", "Destination IP", "Length", "TTL", "Source Port", "Destination Port", "Protocol", "Timestamp", "Modbus Function", "Modbus Data", "Modbus Message Address", "Modbus Error Control", "Packet Payload"]
    
    with open(destination_file, mode='w', newline='') as destination:
        writer = csv.writer(destination)
        writer.writerow(destination_headers)

        def live_packet_handler(pkt):
            packet_handler(pkt, writer)

        # Ağı dinle ve paketleri işle
        sniff(prn=live_packet_handler, count=10, timeout=60)

if __name__ == "__main__":
    source_file = "/home/kaliuser_priv/034215_69.log.part01_sorted(1).csv"
    destination_file = "2015-12-22_034215_69.log.part01_sorted(1)_output_ver3.csv"

    if os.path.exists(source_file):
        print("CSV dosyası mevcut. Veriler CSV dosyasından okunacak.")
        packet_handler_from_csv(source_file, destination_file)
    else:
        print("CSV dosyası mevcut değil. Ağ dinlenecek ve veriler canlı olarak yakalanacak.")
        packet_handler_from_live_capture(destination_file)
