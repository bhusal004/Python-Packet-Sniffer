	
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw
from datetime import datetime

def analyze_packet(packet):
    print("\n" + "=" * 60)
    print("Time:", datetime.now().strftime("%H:%M:%S"))

    # Identify IP addresses
    if IP in packet:
        ip_layer = packet[IP]
        print("Source IP      :", ip_layer.src)
        print("Destination IP :", ip_layer.dst)
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
        print("Source IPv6    :", ip_layer.src)
        print("Destination IPv6:", ip_layer.dst)
    else:
        print("No IP layer found")

    # Identify protocol and ports
    if TCP in packet:
        print("Protocol       : TCP")
        print("Source Port    :", packet[TCP].sport)

        print("Destination Port:", packet[TCP].dport)

    elif UDP in packet:
        print("Protocol       : UDP")
        print("Source Port    :", packet[UDP].sport)
        print("Destination Port:", packet[UDP].dport)

    elif ICMP in packet:
        print("Protocol       : ICMP")

    elif IP in packet or IPv6 in packet:
        print("Protocol       : Other IP protocol")

    # Display limited payload data
    if Raw in packet:
        payload = bytes(packet[Raw].load)
        print("Payload length :", len(payload), "bytes")

        # Show at most 100 bytes as readable text
        preview = payload[:100].decode("utf-8", errors="replace")
        print("Payload preview:", repr(preview))

        # Hexadecimal representation
        print("Payload hex    :", payload[:32].hex())

    else:
        print("Payload        : No Raw payload layer")

def main():
    print("Basic Network Sniffer")
    print("capturing 20 packets")
    print("Capture is limited to IP/IPv6 packets.")

    try:
        sniff(
            filter="ip or ip6",
            prn=analyze_packet,
            count=20,
            store=False
        )
    except PermissionError:
        print("Permission denied. Run with sudo.")
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
    except Exception as error:
        print("Capture error:", error)

if __name__ == "__main__":
    main()
