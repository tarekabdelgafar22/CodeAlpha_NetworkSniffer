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
