from scapy.all import *

def packet_handler(packet):
    print(packet.summary())
    # Save to file
    wrpcap("captured_packets.pcap", packet, append=True)

print("Saving packets to captured_packets.pcap")
sniff(prn=packet_handler, count=20)