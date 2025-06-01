import pandas as pd
import joblib

# Load the live dataset
df_live = pd.read_csv("data/live_network_data.csv")

# Drop 'Label' and 'Attack_Type' columns if present
if "Label" in df_live.columns:
    df_live = df_live.drop(columns=["Label"])
if "Attack_Type" in df_live.columns:
    df_live = df_live.drop(columns=["Attack_Type"])

# Fill missing values with 0
df_live.fillna(0, inplace=True)

# Load the scaler used during training
scaler = joblib.load("models/scaler.pkl")

# Ensure the live dataset has the same features as the training dataset
# Load the balanced dataset to get the feature names
df_balanced = pd.read_csv("data/balanced_dataset.csv")
X_balanced = df_balanced.drop(columns=["Label", "Attack_Type"])

# Align features
missing_features = set(X_balanced.columns) - set(df_live.columns)
extra_features = set(df_live.columns) - set(X_balanced.columns)

# Drop extra features
df_live = df_live.drop(columns=extra_features)

# Add missing features with default values (e.g., 0)
for feature in missing_features:
    df_live[feature] = 0

# Reorder columns to match the training dataset
df_live = df_live[X_balanced.columns]

# Normalize the live dataset using the same scaler
X_live_scaled = scaler.transform(df_live)

# Convert the scaled data back to a DataFrame with feature names
X_live_scaled = pd.DataFrame(X_live_scaled, columns=X_balanced.columns)

# Load the trained models
models = {
    "random_forest": joblib.load("models/random_forest.pkl"),
    "xgboost": joblib.load("models/xgboost.pkl"),
    "mlp": joblib.load("models/mlp.pkl"),
    "ensemble": joblib.load("models/ensemble.pkl")
}

# Hardcoded label mapping
label_mapping = {
    "0": "Benign",
    "1": "DNS",
    "2": "LDAP",
    "3": "MSSQL",
    "4": "NTP",
    "5": "NetBIOS",
    "6": "Portmap",
    "7": "SNMP",
    "8": "Syn",
    "9": "TFTP",
    "10": "UDP",
    "11": "UDP-lag",
    "12": "WebDDoS"
}

# Create a reverse mapping for decoding predictions
reverse_label_mapping = {int(k): v for k, v in label_mapping.items()}

# Debug: Print predictions from base models
rf_predictions = models["random_forest"].predict(X_live_scaled)
xgb_predictions = models["xgboost"].predict(X_live_scaled)
mlp_predictions = models["mlp"].predict(X_live_scaled)

print("\nRandom Forest predictions:", [reverse_label_mapping.get(pred, "Unknown") for pred in rf_predictions[:5]])
print("XGBoost predictions:", [reverse_label_mapping.get(pred, "Unknown") for pred in xgb_predictions[:5]])
print("MLP predictions:", [reverse_label_mapping.get(pred, "Unknown") for pred in mlp_predictions[:5]])

# Test models on live dataset
print("\nTesting models on live dataset:")
for name, model in models.items():
    print(f"\nModel: {name}")
    predictions = model.predict(X_live_scaled)
    
    # Decode predictions using the reverse label mapping
    decoded_predictions = [reverse_label_mapping.get(pred, "Unknown") for pred in predictions]
    
    # Print predictions for the first few samples
    print(f"Predictions for the first 5 samples: {decoded_predictions[:5]}")
    
    # Detect if there are any stacks (anomalies or attacks) in the dataset
    if any(pred != "Benign" for pred in decoded_predictions):  # Assuming "Benign" is the label for normal traffic
        print(f"Stacks (anomalies/attacks) detected in the dataset by {name}!")
    else:
        print(f"No stacks detected by {name}.")

# Save the predictions for further analysis
df_live["Predictions"] = [reverse_label_mapping.get(pred, "Unknown") for pred in models["ensemble"].predict(X_live_scaled)]
df_live.to_csv("data/live_predictions.csv", index=False)
print("\nPredictions saved to 'data/live_predictions.csv'.")