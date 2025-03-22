# Network Sniffer

## Overview
This project is a network sniffer tool implemented in Python. It captures and analyzes network traffic, providing detailed information about each packet. The tool utilizes the **Scapy** library for packet capture and analysis.

---

## Features
- Captures network packets in real-time.
- Provides detailed information about each packet, including:
  - Source and destination IP addresses.
  - Protocol (TCP, UDP, ICMP, etc.).
  - Packet length and time of capture.
  - TTL (Time to Live) and flags.
- Displays source and destination MAC addresses for Ethernet packets.
- Supports capturing and analyzing fragmented IP packets.
- Provides TCP-specific information such as sequence numbers, acknowledgment numbers, and TCP flags.

---

## Installation

### Step 1: Install Python
Make sure you have Python 3.x installed. You can download it from [python.org](https://www.python.org/).

### Step 2: Install Required Libraries
Install the **Scapy** library using pip:
```bash
pip install scapy

### Clone the repository:
   git clone https://github.com/PB448/Code_Alpha_project
   cd Code_Alpha_project

### Run the network sniffer script:
  ## On Linux/Mac
   sudo python3 sniffer.py
  ## On Windows (Run as Administrator):
     ## Install Npcap (Windows Only)
        If you're on Windows, you need to install Npcap for packet capture:
        Visit the Npcap website.
        Download the installer for your system.

       Run the installer and follow the instructions
       python sniffer.py

## The script will start capturing network packets and display detailed information about each packet in real-time.

How It Works
1.	Packet Capture:
o	The tool uses Scapy to capture packets from the network interface.
o	It decodes the packets and extracts details like IP addresses, protocols, and ports.
2.	Packet Analysis:
o	For each packet, the tool analyzes the protocol (TCP, UDP, ICMP, etc.).
3.	Real-Time Display:
o	Captured packets are displayed in real-time with detailed information.

Acknowledgments
•	Thanks to the creators of Scapy for making packet manipulation easy.
•	Inspired by tools like Wireshark.


