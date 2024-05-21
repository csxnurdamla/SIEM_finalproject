import csv
from scapy.all import *

def get_protocol(pkt):
    if IP in pkt:
        if TCP in pkt[IP]:
            return "TCP"
        elif UDP in pkt[IP]:
            return "UDP"
        else:
            return "Unknown"
    else:
        return "Unknown"

def packet_handler(pkt):
    if IP in pkt and Ether in pkt:  
        dest_mac = pkt[Ether].dst  
        src_mac = pkt[Ether].src   
        ether_type = hex(pkt[Ether].type)

        if IP in pkt: 
            ttl = pkt[IP].ttl
            length = pkt[IP].len
            src_ip = pkt[IP].src  
            dst_ip = pkt[IP].dst 
            
            if TCP in pkt:  
                src_port = pkt[TCP].sport  
                dst_port = pkt[TCP].dport  
            elif UDP in pkt:  
                src_port = pkt[UDP].sport  
                dst_port = pkt[UDP].dport  
            else:
                src_port = "N/A"
                dst_port = "N/A"
        else:
            src_ip = "N/A"
            dst_ip = "N/A"
            src_port = "N/A"
            dst_port = "N/A"

        timestamp = pkt.time  

        if ICMP in pkt:
            icmp_type = pkt[ICMP].type
            if icmp_type in [5, 11]:  
                urgency = "High"
                error_type = "Error"
            else:
                urgency = "Low"
                error_type = "Normal"
        else:
            urgency = "N/A"
            error_type = "N/A"

        modbus_message_address, modbus_error_control = parse_modbus(pkt)
        modbus_data = None  # Henüz bu veriyi parse etmedik, dolayısıyla değeri None olarak atıyoruz

        # CSV'ye yazmak için verileri bir listeye ekleyelim
        packet_data = [src_mac, dest_mac, ether_type, src_ip, dst_ip, length, ttl, src_port, dst_port, get_protocol(pkt), timestamp, urgency, error_type, modbus_message_address, modbus_error_control, modbus_data]

        # CSV dosyasına yazma
        with open('packet_data.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(packet_data)

def parse_modbus(pkt):
    if TCP in pkt and (pkt[TCP].dport == 502 or pkt[TCP].sport == 502):
        payload = bytes(pkt[TCP].payload)
        if len(payload) > 7:
            modbus_message_address = int.from_bytes(payload[8:10], byteorder='big')
            modbus_error_control = payload[-2:]
            return modbus_message_address, modbus_error_control
    return None, None

# CSV dosyasına başlık satırı ekleyelim
with open('packet_data.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Source MAC", "Destination MAC", "Ethernet Type", "Source IP", "Destination IP", "Length", "TTL", "Source Port", "Destination Port", "Protocol", "Timestamp", "Urgency", "Error Type", "Modbus Message Address", "Modbus Error Control", "Modbus Data"])

# Sniff fonksiyonunu kullanarak paketleri dinle
sniff(prn=packet_handler, count=10)  # Örneğin ilk 10 paketi dinle
