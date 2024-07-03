# CodeAlpha_Basic_Network_Sniffer
A network sniffer in Python that captures and analyzes network traffic to understand how data flows on a network and how network packets are structured.

## Functionalities
- Captures and logs packets of the specified network interface and protocol, specifically IP, TCP, UDP and Ethernet packets.
- Logs packet summaries with the date & time and provides a detailed structure of the packet.

## Requirements
- scapy library
  To install scapy use command:

  '''sh
  pip install scapy
  

## Usage
To run the network sniffer, use the command:

'''sh
python main.py --interface <network_interface> --count <packet_count>


### Example
'''sh
python main.py --interface eth0 --count 5


## Logging Format
<delimiter>
<timestamp> - Network Sniffer Started
<timestamp> - Packet captured: <packet_summary>
<timestamp> - Packet structure:
<packet_structure>
<timestamp> - Analyzing packet...
<timestamp> - IP Packet: <src_ip> -> <dst_ip>
<timestamp> - TCP Packet: <src_port> -> <dst_port>
<timestamp> - UDP Packet: <src_port> -> <dst_port>
<timestamp> - Ethernet Packet: <src_mac> -> <dst_mac>
<timestamp> - Error: <error_message>
<delimiter>
