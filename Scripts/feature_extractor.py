import json
import time
import pandas as pd
import os
import numpy as np
from kafka import KafkaConsumer
from sklearn.preprocessing import StandardScaler
import joblib

# Define correct CSV path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_FILE = os.path.join(BASE_DIR, "data", "live_network_data.csv")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

# Ensure the "data" directory exists
os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)

# Debug: Print CSV path
print(f"✅ CSV file path: {CSV_FILE}")

# Load the scaler used during training
try:
    scaler = joblib.load(SCALER_PATH)
    print(f"✅ Loaded scaler from {SCALER_PATH}")
except FileNotFoundError:
    print(f"❌ Scaler file not found: {SCALER_PATH}")
    exit(1)

# Kafka configuration
KAFKA_BROKER = 'localhost:9092'
TOPIC_NAME = 'network_traffic'

# Batch size for writing to CSV
BATCH_SIZE = 1000
MAX_ROWS = 500000

consumer = KafkaConsumer(
    TOPIC_NAME,
    bootstrap_servers=KAFKA_BROKER,
    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
    fetch_max_bytes=1048576,  # 1 MB
    max_poll_records=1000
)

# Expected feature order (must match training dataset)
FEATURE_COLUMNS = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min", "Packet Length Max",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Avg Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init Fwd Win Bytes",
    "Init Bwd Win Bytes", "Fwd Act Data Packets", "Fwd Seg Size Min", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

def preprocess_data(packet_data):
    """
    Preprocess the packet data to match the training dataset format.
    """
    try:
        # Extract Source IP from packet data
        source_ip = packet_data.pop("Source IP", None)

        # Convert packet data to DataFrame
        df = pd.DataFrame([packet_data])

        # Ensure all required features exist
        missing_features = [f for f in FEATURE_COLUMNS if f not in df.columns]
        if missing_features:
            print(f"⚠️ Warning: Missing features {missing_features}. Filling with 0.")
            for feature in missing_features:
                df[feature] = 0.0  # Fill missing columns with default value

        # Ensure column order matches training data
        df = df[FEATURE_COLUMNS]

        # Fill missing values
        df.fillna(0, inplace=True)

        # Skip empty data
        if df.empty:
            print("⚠️ Warning: Received empty data. Skipping processing.")
            return None, None

        # Normalize using the trained scaler
        df_scaled = scaler.transform(df)

        # Convert back to DataFrame
        df_scaled = pd.DataFrame(df_scaled, columns=FEATURE_COLUMNS)

        # Add Source IP back to the DataFrame
        df_scaled["Source IP"] = source_ip

        return df_scaled, source_ip

    except Exception as e:
        print(f"❌ Preprocessing error: {e}")
        return None, None

def start_feature_extractor():
    print("📡 Feature extractor listening for packets...")
    batch = []

    for message in consumer:
        processed_data, source_ip = preprocess_data(message.value)
        if processed_data is None:
            continue  # Skip invalid or empty data

        batch.append(processed_data)

        if len(batch) >= BATCH_SIZE:
            try:
                # Convert batch to DataFrame
                df_batch = pd.concat(batch, ignore_index=True)

                # Append to CSV
                df_batch.to_csv(CSV_FILE, mode='a', index=False, header=not os.path.exists(CSV_FILE))

                # Trim the file if it exceeds MAX_ROWS
                if os.path.exists(CSV_FILE) and os.path.getsize(CSV_FILE) > 10_000_000:
                    df = pd.read_csv(CSV_FILE, low_memory=False)
                    if len(df) > MAX_ROWS:
                        df = df.iloc[-MAX_ROWS:]
                        df.to_csv(CSV_FILE, index=False)

                print(f"✅ Batch of {len(batch)} packets saved to {CSV_FILE}")
                batch = []  # Reset batch

            except Exception as e:
                print(f"❌ Error updating CSV: {e}")

if __name__ == "__main__":
    start_feature_extractor()