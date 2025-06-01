import os
import pandas as pd
import joblib
import numpy as np

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LIVE_DATA_PATH = os.path.join(BASE_DIR, "data", "live_network_data.csv")
BALANCED_DATA_PATH = os.path.join(BASE_DIR, "data", "balanced_dataset.csv")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

# Ensure necessary files exist
def check_file_exists(file_path, name):
    if not os.path.exists(file_path):
        print(f"❌ Error: {name} file not found at {file_path}")
        return False
    return True

# Validate files before proceeding
if not all([
    check_file_exists(LIVE_DATA_PATH, "Live dataset"),
    check_file_exists(BALANCED_DATA_PATH, "Balanced dataset"),
    check_file_exists(SCALER_PATH, "Scaler")
]):
    exit(1)

# Load datasets
df_live = pd.read_csv(LIVE_DATA_PATH)
df_balanced = pd.read_csv(BALANCED_DATA_PATH)

# Load trained scaler
scaler = joblib.load(SCALER_PATH)

# **Ensure feature alignment**
balanced_features = list(df_balanced.drop(columns=["Label", "Attack_Type"], errors="ignore").columns)  # Remove target labels
live_features = list(df_live.columns)

missing_in_live = set(balanced_features) - set(live_features)
extra_in_live = set(live_features) - set(balanced_features)

print("\n🔍 **Feature Comparison**")
print(f"✅ Features in both datasets: {len(set(live_features) & set(balanced_features))}")
print(f"⚠️ Missing in Live Dataset: {missing_in_live}")
print(f"⚠️ Extra in Live Dataset: {extra_in_live}")

# **Remove extra features and add missing ones**
df_live = df_live.drop(columns=extra_in_live | {"Label", "Attack_Type"}, errors="ignore")  # Drop target labels
for feature in missing_in_live:
    df_live[feature] = 0  # Add missing features with default values

# **Ensure feature order matches the training dataset**
df_live = df_live[balanced_features]  # Ensure columns match before scaling

# **Scale the live dataset**
df_live_scaled = scaler.transform(df_live)
df_live_scaled = pd.DataFrame(df_live_scaled, columns=balanced_features)

# **Compare Class Distribution (Only in Balanced Dataset)**
if "Label" in df_balanced.columns:
    print("\n🔍 **Class Distribution**")
    print("Balanced Dataset Class Counts:")
    print(df_balanced["Label"].value_counts())

# **Compare SYN Flood Feature Statistics**
syn_feature = "Flow Packets/s"

print("\n🔍 **SYN Flood Feature Comparison**")
if syn_feature in df_live.columns and syn_feature in df_balanced.columns:
    print(f"Live Dataset SYN Feature Stats:\n{df_live[syn_feature].describe()}")
    print(f"\nBalanced Dataset SYN Feature Stats:\n{df_balanced[syn_feature].describe()}")

# **Save Preprocessed Data for Model Testing**
df_live_scaled.to_csv(os.path.join(BASE_DIR, "data", "live_dataset_fixed.csv"), index=False)
df_balanced.to_csv(os.path.join(BASE_DIR, "data", "balanced_dataset_fixed.csv"), index=False)

print("\n✅ **Preprocessed datasets saved! Ready for model testing!**")
