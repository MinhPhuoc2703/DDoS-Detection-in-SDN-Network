from scapy.all import IP, TCP, UDP, ICMP, send
import random
import time

def send_packet(source_ip, destination_ip, protocol):
    """
    Send a real network packet using Scapy.

    :param source_ip: The source IP address.
    :param destination_ip: The destination IP address.
    :param protocol: The protocol (TCP, UDP, or ICMP).
    """
    source_port = random.randint(1024, 65535)
    dest_port = random.randint(1, 65535)
    if protocol == "TCP":
        packet = IP(src=source_ip, dst=destination_ip) / TCP(sport=source_port, dport=dest_port)
    elif protocol == "UDP":
        packet = IP(src=source_ip, dst=destination_ip) / UDP(sport=source_port, dport=dest_port)
    elif protocol == "ICMP":
        packet = IP(src=source_ip, dst=destination_ip) / ICMP(type=8, code=0) / b"Ping"
    else:
        raise ValueError("Unsupported protocol")

    send(packet, count=5)
    print(f"Sent {protocol} packet from {source_ip}:{source_port if protocol in ['TCP', 'UDP'] else ''} to {destination_ip}:{dest_port if protocol in ['TCP', 'UDP'] else ''}")


def main():
    ip_addresses = [
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.4",
        "10.0.2.2",
        "192.168.2.2",
    ]

    protocols = ["TCP", "UDP", "ICMP"]

    num_packets = 10000

    for i in range(num_packets):
        # Randomly select source and destination IPs, ensuring they are not the same
        source_ip, destination_ip = random.sample(ip_addresses, 2)

        # Randomly select a protocol
        protocol = random.choice(protocols)

        # Send the packet
        print(f"Loop: {i}")
        send_packet(source_ip, destination_ip, protocol)

        # Optional: Wait for a short period to simulate delay
        time.sleep(1)

if __name__ == "__main__":
    main()
