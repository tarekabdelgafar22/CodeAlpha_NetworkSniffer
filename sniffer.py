from scapy.all import sniff
from datetime import datetime

print("""
====================================
       Network Sniffer Started
====================================
""")

packet_count = 0


# None = Capture all protocols
FILTER_PROTOCOL = None


# Log file for saving packets
log_file = open("packets.txt", "a")


def packet_callback(packet):

    global packet_count

    if not packet.haslayer("IP"):
        return


    # Protocol filtering
    if FILTER_PROTOCOL == "tcp" and not packet.haslayer("TCP"):
        return

    if FILTER_PROTOCOL == "udp" and not packet.haslayer("UDP"):
        return

    if FILTER_PROTOCOL == "icmp" and not packet.haslayer("ICMP"):
        return


    packet_count += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    source_ip = packet["IP"].src
    destination_ip = packet["IP"].dst


    protocol = packet["IP"].proto

    if protocol == 6:
        protocol = "TCP"

    elif protocol == 17:
        protocol = "UDP"

    elif protocol == 1:
        protocol = "ICMP"

    else:
        protocol = str(protocol)


    print("\n" + "=" * 60)
    print(f"Packet Number    : {packet_count}")
    print(f"Timestamp        : {timestamp}")
    print(f"Source IP        : {source_ip}")
    print(f"Destination IP   : {destination_ip}")
    print(f"Protocol         : {protocol}")


    log_data = f"""
============================================================
Packet Number    : {packet_count}
Timestamp        : {timestamp}

Source IP        : {source_ip}
Destination IP   : {destination_ip}
Protocol         : {protocol}
"""


    if packet.haslayer("TCP"):

        source_port = packet["TCP"].sport
        destination_port = packet["TCP"].dport

        print(f"Source Port      : {source_port}")
        print(f"Destination Port : {destination_port}")

        log_data += f"""
Source Port      : {source_port}
Destination Port : {destination_port}
"""


    elif packet.haslayer("UDP"):

        source_port = packet["UDP"].sport
        destination_port = packet["UDP"].dport

        print(f"Source Port      : {source_port}")
        print(f"Destination Port : {destination_port}")

        log_data += f"""
Source Port      : {source_port}
Destination Port : {destination_port}
"""


    if packet.haslayer("Raw"):

        try:
            payload = packet["Raw"].load.decode(errors="ignore")

            print(f"Payload          : {payload[:100]}")

            log_data += f"""
Payload          : {payload[:100]}
"""

        except:
            pass


    # Save packet information
    log_file.write(log_data)
    log_file.flush()



# Start packet sniffing
sniff(prn=packet_callback)
