from scapy.all import sniff, IP, TCP, UDP
from modules.utlmdl import print_title

def packet_summary(packet):
    """
    Returns a short summary of the packet for logging or display.
    """
    if IP in packet:
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else str(packet[IP].proto)
        summary = f"[{packet[IP].src} -> {packet[IP].dst}] Protocol: {proto}"
        print(summary)
        return summary
    return None

def start_sniffer(interface="eth0", count=0):
    """
    Start live packet capture on the specified interface.
    count=0 means indefinite capture until Ctrl+C.
    """
    print_title(f"Packet Sniffer on {interface}")
    print("[*] Press Ctrl+C to stop sniffing.")
    sniff(iface=interface, prn=packet_summary, count=count, store=False)
