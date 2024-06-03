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



def convert_row(source_row):
    
    transformed_row = {
        "Source MAC": source_row["src"],
        "Destination MAC": source_row["dst"],
        "EtherType": "",  
        "Source IP": source_row["src"],
        "Destination IP": source_row["dst"],
        "Length": "",
        "TTL": "",
        "Source Port": source_row["s_port"],
        "Destination Port": source_row["Tag"],
        "Protocol": source_row["proto"],
        "Timestamp": "",
        "Modbus Function": source_row["Modbus_Function_Code"],
        "Modbus Data": source_row["Modbus_Value"],
        "Modbus Message Address": source_row["Modbus_Transaction_ID"],  # Yeni alanlar eklendi
        "Modbus Error Control": "",
        "Packet Payload": source_row["Modbus_Function_Description"]  # Yeni alanlar eklendi
    }
    return transformed_row

def packet_handler_from_csv():
    source_file = "/home/kaliuser_priv/2015-12-22_034215_69.log.part01_sorted(1).csv"
    destination_file = "2015-12-22_034215_69.log.part01_sorted(1)_output.csv"

    with open(source_file, mode='r', newline='') as source, open(destination_file, mode='w', newline='') as destination:
        reader = csv.DictReader(source)
        destination_headers = ["Source MAC", "Destination MAC", "EtherType", "Source IP", "Destination IP", "Length", "TTL", "Source Port", "Destination Port", "Protocol", "Timestamp", "Modbus Function", "Modbus Data", "Modbus Message Address", "Modbus Error Control", "Packet Payload"]
        writer = csv.DictWriter(destination, fieldnames=destination_headers)
        
        writer.writeheader()

        for row in reader:
            transformed_row = convert_row(row)
            writer.writerow(transformed_row)

packet_handler_from_csv()



