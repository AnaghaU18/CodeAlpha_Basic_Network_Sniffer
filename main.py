import argparse
import logging
from scapy.all import sniff
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
from datetime import datetime

# Configure logging to output to a file named 'network_sniffer.log'
logging.basicConfig(
    filename='network_sniffer.log',
    level=logging.INFO,
    format='%(message)s',  # Log format set to include only the message
    datefmt='%Y-%m-%d %H:%M:%S'  # Date format for log entries
)

def setup_sniffer(interface, packet_count):
    """
    Set up the network sniffer.

    :param interface: Network interface to sniff on
    :param packet_count: Number of packets to capture (0 for infinite)
    """
    logging.info("#" * 40)  # Log delimiter
    logging.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Network Sniffer Started")
    # Start sniffing on the specified interface and handle packets with packet_handler
    sniff(iface=interface, prn=packet_handler, count=packet_count)
    # Log delimiter after sniffing completes
    # logging.info("#" * 40)

def packet_handler(packet):
    """
    Handle each captured packet.

    :param packet: The captured packet
    """
    # Print and log a summary of the packet
    print(f"Packet summary: {packet.summary()}")
    logging.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Packet captured: {packet.summary()}")
    
    # Get the packet structure as a formatted string and log it
    packet_structure = packet.show(dump=True)
    logging.info(f"Packet structure:\n{packet_structure}")
    
    # Analyze the packet
    analyze_packet(packet)
    logging.info("#" * 40)  # Log delimiter after analyzing each packet

def analyze_packet(packet):
    """
    Analyze the contents of the packet.

    :param packet: The captured packet
    """
    logging.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Analyzing packet...")
    if packet.haslayer(IP):
        # If the packet has an IP layer, log the source and destination IP addresses
        ip_layer = packet.getlayer(IP)
        logging.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - IP Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        if packet.haslayer(TCP):
            # If the packet has a TCP layer, log the source and destination ports
            tcp_layer = packet.getlayer(TCP)
            logging.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")

        if packet.haslayer(UDP):
            # If the packet has a UDP layer, log the source and destination ports
            udp_layer = packet.getlayer(UDP)
            logging.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - UDP Packet: {udp_layer.sport} -> {udp_layer.dport}")

    elif packet.haslayer(Ether):
        # If the packet has an Ethernet layer, log the source and destination MAC addresses
        ether_layer = packet.getlayer(Ether)
        logging.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Ethernet Packet: {ether_layer.src} -> {ether_layer.dst}")

def start_sniffer(interface, packet_count):
    """
    Start the network sniffer.

    :param interface: Network interface to sniff on
    :param packet_count: Number of packets to capture (0 for infinite)
    """
    setup_sniffer(interface, packet_count)
    print("Log saved!")  # Print message indicating log has been saved

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Network Sniffer")
    parser.add_argument('-interface', '--interface', type=str, required=True, help='Network interface to sniff on')
    parser.add_argument('-count', '--count', type=int, default=0, help='Number of packets to capture (default: 0 for infinite)')
    
    args = parser.parse_args()
    
    try:
        # Start the sniffer with the provided arguments
        start_sniffer(args.interface, args.count)
    except Exception as e:
        # Log and print any errors that occur
        logging.error(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Error: {str(e)}")
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()  # Run the main function if the script is executed directly
