from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import csv

ip_counter = defaultdict(int)

# Counters for traffic statistics
total_packets = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
start_time = time.time()

def identify_service(port):

    servicees ={
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        22: "SSH",
        21: "FTP",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        3306: "MySQL",
    }

    return servicees.get(port, "Unknown")

def log_packet(time_val, src, dst, protocol, port, service, size, pps):

    with open("traffic_log.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            time_val, src, dst, protocol, port, service, size,pps
        ])

def show_packet(packet):

    global total_packets, tcp_count, udp_count, icmp_count

    elapsed_time = time.time() - start_time
    pps = total_packets / elapsed_time

    if packet.haslayer(IP):

        total_packets += 1

        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)

        # count IP activity
        ip_counter[src] += 1
        ip_counter[dst] += 1

        protocol = "Other"
        port = "N/A"
        service = "Unknown"

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp_count += 1
            port = packet[TCP].dport
            service = identify_service(port)

        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp_count += 1
            port = packet[UDP].dport
            service = identify_service(port)

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            icmp_count += 1

        print("Packet Captured")
        print("Source IP:", src)
        print("Destination IP:", dst)
        print("Protocol:", protocol)
        print("Size:", size, "bytes")
        print("Port:", port)

        if protocol in ["TCP", "UDP", "ICMP", "Other", "Unknown"]:
            service = identify_service(port)
            print("Service:", service)

        print()

        print("Traffic Stats:")
        print(f"Total Packets: {total_packets}")
        print(f"TCP: {tcp_count} | UDP: {udp_count} | ICMP: {icmp_count}")

        print()

        print(f"Packets/sec: {pps:.2f}")

        log_packet(
            time.strftime("%H:%M:%S"),
             src,
             dst,
             protocol,
             port,
             service,
             size,
             pps
        )

        print()

        print("Top Active IPs:")

        top_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:3]

        for ip, count in top_ips:
              print(ip, "→", count, "packets")

        print("---------------------------")
        
sniff(prn=show_packet)