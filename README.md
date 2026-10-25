CodeAlpha_NetworkSniffer
Task 1: Basic Network Sniffer | CodeAlpha Cyber Security Internship

A Python network sniffer built with Scapy. It captures live IP traffic, breaks each packet down into its layers, prints the key details to the terminal, and logs them to a file.

Features
Captures live network traffic using Scapy
Displays source and destination IP addresses
Identifies the protocol (TCP, UDP, ICMP, or protocol number)
Shows source and destination ports for TCP and UDP packets
Shows the first 100 characters of the payload when available
Optional protocol filter (tcp, udp, icmp) via FILTER_PROTOCOL
Timestamps every packet and saves everything to packets.txt
Requirements
Python 3
Scapy
Root privileges (raw sockets need them)
pip install scapy
Usage
sudo python3 sniffer.py
Press Ctrl + C to stop.

To capture one protocol only, edit this line in sniffer.py:

FILTER_PROTOCOL = "tcp"   # "tcp", "udp", "icmp", or None for all
Example Output
Captured on Kali Linux:

Sniffer Output

Sample packet:

============================================================
Packet Number    : 3
Timestamp        : 2026-10-23 21:05:07
Source IP        : 192.168.1.5
Destination IP   : 51.178.91.234
Protocol         : TCP
Source Port      : 48526
Destination Port : 443
Note: Payloads on port 443 look like random characters because the traffic is encrypted (HTTPS/QUIC). The sniffer sees the headers, but not the encrypted content.

How It Works
sniff() captures packets and passes each one to packet_callback.
Non-IP packets are skipped.
The IP layer gives the addresses and the protocol number, which is mapped to a name.
The TCP/UDP layers give the ports.
The Raw layer gives the payload, decoded as text.
What I Learned
How data moves through the network as layered packets
The structure of IP, TCP, and UDP headers
Reading and filtering live traffic with Scapy
Why encrypted traffic hides its payload from a sniffer
Disclaimer
For educational purposes only. Capture traffic only on networks you own or have permission to monitor.
