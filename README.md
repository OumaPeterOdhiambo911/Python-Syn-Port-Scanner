from scapy.all import IP, TCP, sr1
import sys
from datetime import datetime

# Define common services for open ports (for better reporting)
SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 
    443: "HTTPS", 3389: "RDP"
}

def syn_scan_ports(target, start_port, end_port):
    """
    Performs a SYN/Stealth scan using Scapy on a range of ports.
    """
    print(f"--- Starting SYN Scan on {target} at {datetime.now()} ---")
    
    # We rely on Scapy to resolve the target IP
    target_ip = target
    open_ports = []

    # Iterate through the port range
    for port in range(start_port, end_port + 1):
        # 1. Craft the packet: IP layer + TCP layer (with the SYN flag set)
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(dport=port, flags="S") 
        
        # 2. Combine and send the packet
        # sr1 sends the packet and waits for only the first response.
        # timeout is shorter as SYN scans are quick.
        # verbose=False suppresses Scapy's default output.
        response = sr1(ip_layer / tcp_layer, timeout=0.1, verbose=False)
        
        if response:
            # 3. Analyze the response:
            # A reset flag (R) means the port is closed.
            # An ACK-SYN flag (SA or 0x12) means the port is open.
            
            # Check for the TCP layer and the 'SA' flag (0x12)
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                service = SERVICE_NAMES.get(port, "Unknown")
                print(f"[+] Port {port} ({service}): Open")
                open_ports.append(port)
        
    print("--- Scan Complete ---")
    if open_ports:
        print(f"Open ports found: {open_ports}")
    else:
        print("No open ports found in the specified range.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python scapy_scanner.py <target> <start_port> <end_port>")
        print("Example: python scapy_scanner.py 127.0.0.1 1 1024")
        sys.exit()

    target = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    
    try:
        syn_scan_ports(target, start_port, end_port)
    except Exception as e:
        print(f"[!] An error occurred. Ensure you have root/admin privileges for Scapy operations. Error: {e}")
