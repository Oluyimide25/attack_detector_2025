from scapy.all import sniff, IP, TCP, UDP
import time
from kafka import KafkaProducer
import numpy as np
import json

KAFKA_BROKER = 'localhost:9092'
TOPIC_NAME = 'network_traffic'

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# Track flow statistics
flow_stats = {}

def extract_features(packet):
    """ Extracts network features from a packet """
    try:
        if not packet.haslayer(IP):
            return None  # Ignore non-IP packets

        # Protocol identification
        protocol = 6 if packet.haslayer(TCP) else 17 if packet.haslayer(UDP) else 0

        src_ip = packet[IP].src  # Extract Source IP
        dst_ip = packet[IP].dst
        packet_size = len(packet)

        # Flow key for tracking
        flow_key = f"{src_ip}-{dst_ip}-{protocol}"

        # Initialize flow statistics if not already present
        if flow_key not in flow_stats:
            flow_stats[flow_key] = {
                "start_time": time.time() * 1000,  # Convert to milliseconds
                "fwd_packets": [],
                "bwd_packets": [],
                "fwd_packet_sizes": [],
                "bwd_packet_sizes": [],
                "fwd_iat": [],
                "bwd_iat": [],
                "last_fwd_time": time.time() * 1000,
                "last_bwd_time": time.time() * 1000,
            }

        # Update flow statistics
        current_time = time.time() * 1000
        flow_duration = current_time - flow_stats[flow_key]["start_time"]

        if src_ip == packet[IP].src:
            # Forward packet
            flow_stats[flow_key]["fwd_packets"].append(packet)
            flow_stats[flow_key]["fwd_packet_sizes"].append(packet_size)
            fwd_iat = current_time - flow_stats[flow_key]["last_fwd_time"]
            flow_stats[flow_key]["fwd_iat"].append(fwd_iat)
            flow_stats[flow_key]["last_fwd_time"] = current_time
        else:
            # Backward packet
            flow_stats[flow_key]["bwd_packets"].append(packet)
            flow_stats[flow_key]["bwd_packet_sizes"].append(packet_size)
            bwd_iat = current_time - flow_stats[flow_key]["last_bwd_time"]
            flow_stats[flow_key]["bwd_iat"].append(bwd_iat)
            flow_stats[flow_key]["last_bwd_time"] = current_time

        # Calculate derived features
        fwd_packet_sizes = flow_stats[flow_key]["fwd_packet_sizes"]
        bwd_packet_sizes = flow_stats[flow_key]["bwd_packet_sizes"]
        fwd_iat = flow_stats[flow_key]["fwd_iat"]
        bwd_iat = flow_stats[flow_key]["bwd_iat"]

        # Extract TCP flags (updated for Scapy 2.4.5+)
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags  # Flags are stored as a string (e.g., 'SA' for SYN-ACK)
            syn_flag = 1 if 'S' in tcp_flags else 0
            fin_flag = 1 if 'F' in tcp_flags else 0
            rst_flag = 1 if 'R' in tcp_flags else 0
            psh_flag = 1 if 'P' in tcp_flags else 0
            ack_flag = 1 if 'A' in tcp_flags else 0
            urg_flag = 1 if 'U' in tcp_flags else 0
            ece_flag = 1 if 'E' in tcp_flags else 0
            cwe_flag = 1 if 'C' in tcp_flags else 0
        else:
            syn_flag = fin_flag = rst_flag = psh_flag = ack_flag = urg_flag = ece_flag = cwe_flag = 0

        # Ensure all features are extracted and match the balanced dataset
        features = {
            "Source IP": src_ip,  # Add Source IP to the features
            "Protocol": protocol,
            "Flow Duration": flow_duration,
            "Total Fwd Packets": len(fwd_packet_sizes),
            "Total Backward Packets": len(bwd_packet_sizes),
            "Fwd Packets Length Total": sum(fwd_packet_sizes),
            "Bwd Packets Length Total": sum(bwd_packet_sizes),
            "Fwd Packet Length Max": max(fwd_packet_sizes) if fwd_packet_sizes else 0,
            "Fwd Packet Length Min": min(fwd_packet_sizes) if fwd_packet_sizes else 0,
            "Fwd Packet Length Mean": np.mean(fwd_packet_sizes) if fwd_packet_sizes else 0,
            "Fwd Packet Length Std": np.std(fwd_packet_sizes) if fwd_packet_sizes else 0,
            "Bwd Packet Length Max": max(bwd_packet_sizes) if bwd_packet_sizes else 0,
            "Bwd Packet Length Min": min(bwd_packet_sizes) if bwd_packet_sizes else 0,
            "Bwd Packet Length Mean": np.mean(bwd_packet_sizes) if bwd_packet_sizes else 0,
            "Bwd Packet Length Std": np.std(bwd_packet_sizes) if bwd_packet_sizes else 0,
            "Flow Bytes/s": (sum(fwd_packet_sizes) + sum(bwd_packet_sizes)) / (flow_duration / 1000) if flow_duration > 0 else 0,
            "Flow Packets/s": (len(fwd_packet_sizes) + len(bwd_packet_sizes)) / (flow_duration / 1000) if flow_duration > 0 else 0,
            "Flow IAT Mean": np.mean(fwd_iat + bwd_iat) if fwd_iat or bwd_iat else 0,
            "Flow IAT Std": np.std(fwd_iat + bwd_iat) if fwd_iat or bwd_iat else 0,
            "Flow IAT Max": max(fwd_iat + bwd_iat) if fwd_iat or bwd_iat else 0,
            "Flow IAT Min": min(fwd_iat + bwd_iat) if fwd_iat or bwd_iat else 0,
            "Fwd IAT Total": sum(fwd_iat),
            "Fwd IAT Mean": np.mean(fwd_iat) if fwd_iat else 0,
            "Fwd IAT Std": np.std(fwd_iat) if fwd_iat else 0,
            "Fwd IAT Max": max(fwd_iat) if fwd_iat else 0,
            "Fwd IAT Min": min(fwd_iat) if fwd_iat else 0,
            "Bwd IAT Total": sum(bwd_iat),
            "Bwd IAT Mean": np.mean(bwd_iat) if bwd_iat else 0,
            "Bwd IAT Std": np.std(bwd_iat) if bwd_iat else 0,
            "Bwd IAT Max": max(bwd_iat) if bwd_iat else 0,
            "Bwd IAT Min": min(bwd_iat) if bwd_iat else 0,
            "Fwd PSH Flags": psh_flag,
            "Bwd PSH Flags": 0,  # Placeholder (requires bidirectional tracking)
            "Fwd URG Flags": urg_flag,
            "Bwd URG Flags": 0,  # Placeholder (requires bidirectional tracking)
            "Fwd Header Length": len(packet[TCP].payload) if packet.haslayer(TCP) else len(packet[UDP].payload) if packet.haslayer(UDP) else 0,
            "Bwd Header Length": 0,  # Placeholder (requires bidirectional tracking)
            "Fwd Packets/s": len(fwd_packet_sizes) / (flow_duration / 1000) if flow_duration > 0 else 0,
            "Bwd Packets/s": len(bwd_packet_sizes) / (flow_duration / 1000) if flow_duration > 0 else 0,
            "Packet Length Min": min(fwd_packet_sizes + bwd_packet_sizes) if fwd_packet_sizes or bwd_packet_sizes else 0,
            "Packet Length Max": max(fwd_packet_sizes + bwd_packet_sizes) if fwd_packet_sizes or bwd_packet_sizes else 0,
            "Packet Length Mean": np.mean(fwd_packet_sizes + bwd_packet_sizes) if fwd_packet_sizes or bwd_packet_sizes else 0,
            "Packet Length Std": np.std(fwd_packet_sizes + bwd_packet_sizes) if fwd_packet_sizes or bwd_packet_sizes else 0,
            "Packet Length Variance": np.var(fwd_packet_sizes + bwd_packet_sizes) if fwd_packet_sizes or bwd_packet_sizes else 0,
            "FIN Flag Count": fin_flag,
            "SYN Flag Count": syn_flag,
            "RST Flag Count": rst_flag,
            "PSH Flag Count": psh_flag,
            "ACK Flag Count": ack_flag,
            "URG Flag Count": urg_flag,
            "CWE Flag Count": cwe_flag,
            "ECE Flag Count": ece_flag,
            "Down/Up Ratio": len(bwd_packet_sizes) / len(fwd_packet_sizes) if len(fwd_packet_sizes) > 0 else 0,
            "Avg Packet Size": np.mean(fwd_packet_sizes + bwd_packet_sizes) if fwd_packet_sizes or bwd_packet_sizes else 0,
            "Avg Fwd Segment Size": np.mean(fwd_packet_sizes) if fwd_packet_sizes else 0,
            "Avg Bwd Segment Size": np.mean(bwd_packet_sizes) if bwd_packet_sizes else 0,
            "Fwd Avg Bytes/Bulk": 0,  # Placeholder (requires bulk transfer tracking)
            "Fwd Avg Packets/Bulk": 0,  # Placeholder (requires bulk transfer tracking)
            "Fwd Avg Bulk Rate": 0,  # Placeholder (requires bulk transfer tracking)
            "Bwd Avg Bytes/Bulk": 0,  # Placeholder (requires bulk transfer tracking)
            "Bwd Avg Packets/Bulk": 0,  # Placeholder (requires bulk transfer tracking)
            "Bwd Avg Bulk Rate": 0,  # Placeholder (requires bulk transfer tracking)
            "Subflow Fwd Packets": len(fwd_packet_sizes),
            "Subflow Fwd Bytes": sum(fwd_packet_sizes),
            "Subflow Bwd Packets": len(bwd_packet_sizes),
            "Subflow Bwd Bytes": sum(bwd_packet_sizes),
            "Init Fwd Win Bytes": packet[TCP].window if packet.haslayer(TCP) else 0,
            "Init Bwd Win Bytes": 0,  # Placeholder (requires bidirectional tracking)
            "Fwd Act Data Packets": len(fwd_packet_sizes),
            "Fwd Seg Size Min": min(fwd_packet_sizes) if fwd_packet_sizes else 0,
            "Active Mean": np.mean(fwd_iat + bwd_iat) if fwd_iat or bwd_iat else 0,
            "Active Std": np.std(fwd_iat + bwd_iat) if fwd_iat or bwd_iat else 0,
            "Active Max": max(fwd_iat + bwd_iat) if fwd_iat or bwd_iat else 0,
            "Active Min": min(fwd_iat + bwd_iat) if fwd_iat or bwd_iat else 0,
            "Idle Mean": 0,  # Placeholder (requires idle time tracking)
            "Idle Std": 0,  # Placeholder (requires idle time tracking)
            "Idle Max": 0,  # Placeholder (requires idle time tracking)
            "Idle Min": 0,  # Placeholder (requires idle time tracking)
        }

        return features

    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def send_to_kafka(data):
    """ Sends extracted features to Kafka """
    try:
        producer.send(TOPIC_NAME, value=data)
        print(f"Sent to Kafka: {data}")
    except Exception as e:
        print(f"Kafka error: {e}")

def packet_callback(packet):
    """ Callback function for Scapy sniffing """
    extracted_data = extract_features(packet)
    if extracted_data:
        send_to_kafka(extracted_data)

if __name__ == "__main__":
    print("Starting live packet capture...")
    sniff(prn=packet_callback, store=False)