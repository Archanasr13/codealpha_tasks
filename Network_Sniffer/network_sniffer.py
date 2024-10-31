from scapy.all import sniff

def packet_handler(packet):
    print(packet.summary())

def start_sniffer(interface):
    sniff(iface=interface, prn=packet_handler, store=0)

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ")
    start_sniffer(interface)
