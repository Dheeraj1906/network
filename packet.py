import pyshark

# Start packet capture on 'en0' (Wi-Fi interface)
print("Starting packet capture on en0...")
capture = pyshark.LiveCapture(interface='en0')  # 'en0' is typically Wi-Fi on macOS

# Capture exactly 10 packets
capture.sniff(packet_count=10)

# Display captured packets
print("Captured packets, now displaying...")
for packet in capture:
    print("Packet Summary:")
    
    # Check if the packet has an IP layer
    if hasattr(packet, 'ip'):
        print("Source IP:", packet.ip.src)
        print("Destination IP:", packet.ip.dst)

    # Check the transport layer (TCP/UDP) and print relevant details
    if hasattr(packet, 'transport_layer'):
        print("Protocol:", packet.transport_layer)
        
        # Access TCP/UDP transport layer for source and destination ports
        if packet.transport_layer == 'TCP' or packet.transport_layer == 'UDP':
            transport_layer = getattr(packet, packet.transport_layer.lower())
            print("Source Port:", transport_layer.srcport)
            print("Destination Port:", transport_layer.dstport)
    
    # Optional: Display additional info like Ethernet and Application layer (e.g., HTTP)
    if hasattr(packet, 'eth'):
        print("Ethernet Source MAC:", packet.eth.src)
        print("Ethernet Destination MAC:", packet.eth.dst)

    if hasattr(packet, 'http'):
        print("HTTP Host:", packet.http.host)
        print("HTTP Method:", packet.http.request_method)

    print("-" * 50)  # Separator for clarity

print("Capture complete.")
