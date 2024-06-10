from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")

def main():
    print("Starting network sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()