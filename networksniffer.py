#!/usr/bin/env python3
"""
Basic Network Packet Sniffer
For CodeAlpha Internship - Task 1
Run with: sudo python3 network_sniffer.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import sys
import platform

# Color codes for beautiful terminal output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

class NetworkSniffer:
    def __init__(self):
        self.packet_count = 0
        self.packets_data = []
        
    def analyze_packet(self, packet):
        """Analyze each captured packet"""
        self.packet_count += 1
        
        # Header for each packet
        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{GREEN}[{datetime.now().strftime('%H:%M:%S')}] Packet #{self.packet_count}{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")
        
        # Check if packet has IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ttl = packet[IP].ttl
            
            # Determine protocol
            protocol_num = packet[IP].proto
            if protocol_num == 6:
                protocol = "TCP"
                color = GREEN
            elif protocol_num == 17:
                protocol = "UDP"
                color = BLUE
            elif protocol_num == 1:
                protocol = "ICMP"
                color = YELLOW
            else:
                protocol = f"Protocol-{protocol_num}"
                color = RESET
            
            print(f"{color}📡 Protocol: {protocol}{RESET}")
            print(f"📍 Source IP: {src_ip}")
            print(f"🎯 Destination IP: {dst_ip}")
            print(f"⏱️  TTL: {ttl}")
            
            # TCP Packet Analysis
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                print(f"🔌 Source Port: {src_port}")
                print(f"🔌 Destination Port: {dst_port}")
                print(f"🚩 TCP Flags: {flags}")
                
                # Service Detection
                if dst_port == 80:
                    print(f"{YELLOW}🌐 HTTP Web Traffic Detected{RESET}")
                elif dst_port == 443:
                    print(f"{GREEN}🔒 HTTPS Secure Traffic{RESET}")
                elif dst_port == 22:
                    print(f"{YELLOW}🔑 SSH Connection{RESET}")
                elif dst_port == 3306:
                    print(f"🗄️  MySQL Database{RESET}")
                    
                # Show payload data
                if Raw in packet:
                    payload = packet[Raw].load
                    print(f"\n📦 Payload (first 100 bytes):")
                    print(f"{payload[:100]}")
                    self.packets_data.append({
                        'time': datetime.now(),
                        'src': src_ip,
                        'dst': dst_ip,
                        'protocol': protocol,
                        'payload': payload[:50]
                    })
            
            # UDP Packet Analysis
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
                print(f"🔌 Source Port: {src_port}")
                print(f"🔌 Destination Port: {dst_port}")
                
                # Service Detection
                if dst_port == 53 or src_port == 53:
                    print(f"{BLUE}🌐 DNS Query Detected{RESET}")
                elif dst_port == 123:
                    print(f"🕐 NTP Time Sync{RESET}")
                    
                if Raw in packet:
                    payload = packet[Raw].load
                    print(f"\n📦 Payload (first 100 bytes):")
                    print(f"{payload[:100]}")
            
            # ICMP Packet Analysis
            elif ICMP in packet:
                icmp_type = packet[ICMP].type
                if icmp_type == 8:
                    print(f"{YELLOW}📤 Echo Request (Ping){RESET}")
                elif icmp_type == 0:
                    print(f"{GREEN}📥 Echo Reply (Pong){RESET}")
                else:
                    print(f"ICMP Type: {icmp_type}")
            
            print(f"{CYAN}{'='*70}{RESET}")
            
        else:
            print(f"{RED}⚠️ Non-IP Packet (Ethernet frame only){RESET}")
    
    def start_sniffing(self, interface=None, packet_count=20, timeout=30):
        """Start capturing network packets"""
        
        # Display banner
        print(f"""
        {GREEN}╔══════════════════════════════════════════════════╗
        ║     CodeAlpha Network Packet Sniffer Active      ║
        ║               Cyber Security Tool                 ║
        ╚══════════════════════════════════════════════════╝{RESET}
        
        📡 Interface: {interface if interface else 'Default'}
        📊 Packet Limit: {packet_count}
        ⏱️  Timeout: {timeout} seconds
        💡 Press Ctrl+C to stop early
        
        {YELLOW}🟢 Listening for network traffic...{RESET}
        """)
        
        try:
            # Start sniffing
            sniff(iface=interface, 
                  prn=self.analyze_packet, 
                  count=packet_count,
                  store=False,
                  timeout=timeout)
            
            # Summary
            print(f"\n{GREEN}{'='*70}{RESET}")
            print(f"{GREEN}✅ CAPTURE COMPLETE{RESET}")
            print(f"{GREEN}📊 Total packets captured: {self.packet_count}{RESET}")
            print(f"{GREEN}{'='*70}{RESET}")
            
            # Show summary of interesting packets
            if self.packets_data:
                print(f"\n{YELLOW}📋 Interesting Packets Summary:{RESET}")
                for i, p in enumerate(self.packets_data[:5], 1):
                    print(f"  {i}. {p['protocol']} | {p['src']} → {p['dst']}")
            
        except KeyboardInterrupt:
            print(f"\n{YELLOW}⚠️ Sniffing stopped by user{RESET}")
            print(f"{GREEN}📊 Total packets captured: {self.packet_count}{RESET}")
        except PermissionError:
            print(f"{RED}❌ ERROR: Permission denied!{RESET}")
            print(f"{YELLOW}💡 Run this command with: sudo python3 network_sniffer.py{RESET}")
        except Exception as e:
            print(f"{RED}❌ ERROR: {e}{RESET}")

def check_requirements():
    """Check if scapy is installed"""
    try:
        import scapy
        return True
    except ImportError:
        return False

def main():
    """Main function"""
    
    # Check Python version
    print(f"{CYAN}🔍 System Information:{RESET}")
    print(f"  Python Version: {platform.python_version()}")
    print(f"  Operating System: {platform.system()} {platform.release()}")
    
    # Check if scapy is installed
    if not check_requirements():
        print(f"\n{RED}❌ Scapy library not found!{RESET}")
        print(f"{YELLOW}💡 Install it using:{RESET}")
        print(f"  pip install scapy")
        print(f"  or")
        print(f"  pip3 install scapy")
        return
    
    print(f"{GREEN}✅ All requirements satisfied!{RESET}\n")
    
    # Create sniffer instance
    sniffer = NetworkSniffer()
    
    # Ask user for preferences
    print(f"{CYAN}📡 Network Interface Configuration:{RESET}")
    print("  1. Use default interface")
    print("  2. Specify interface (eth0, wlan0, etc.)")
    
    choice = input(f"\n{YELLOW}Enter choice (1 or 2, default: 1): {RESET}").strip()
    
    interface = None
    if choice == '2':
        interface = input(f"{YELLOW}Enter interface name: {RESET}").strip()
    
    # Ask for packet count
    packet_input = input(f"{YELLOW}Number of packets to capture (default: 20): {RESET}").strip()
    packet_count = int(packet_input) if packet_input.isdigit() else 20
    
    # Start sniffing
    sniffer.start_sniffing(interface=interface, packet_count=packet_count)

if __name__ == "__main__":
    main()