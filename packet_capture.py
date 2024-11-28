import pyshark

def capture_packets(interface, packet_count=5, filters=None):
    print(f"Starting packet capture on {interface} with filters: {filters}...")
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=filters)
    capture.sniff(packet_count=packet_count)

    packet_data = []
    for packet in capture:
        try:
            packet_info = {
                "packet_number": packet.number,
                "timestamp": str(packet.sniff_time),
                "source": getattr(packet.ip, "src", "N/A"),
                "destination": getattr(packet.ip, "dst", "N/A"),
                "protocol": packet.highest_layer,
                "length": packet.length,
            }
        except AttributeError:
            packet_info = {
                "packet_number": packet.number,
                "timestamp": str(packet.sniff_time),
                "info": "Non-IP packet detected"
            }
        packet_data.append(packet_info)

    return packet_data
