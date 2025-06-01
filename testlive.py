import os
import pandas as pd
import joblib
import numpy as np

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LIVE_DATA_PATH = os.path.join(BASE_DIR, "data", "live_network_data.csv")
BALANCED_DATA_PATH = os.path.join(BASE_DIR, "data", "balanced_dataset.csv")

# Ensure necessary files exist
def check_file_exists(file_path, name):
    if not os.path.exists(file_path):
        print(f"❌ Error: {name} file not found at {file_path}")
        return False
    return True

# Validate required files before proceeding
if not all([
    check_file_exists(LIVE_DATA_PATH, "Live dataset"),
    check_file_exists(BALANCED_DATA_PATH, "Balanced dataset")
]):
    exit(1)

# Load balanced dataset for feature reference
df_balanced = pd.read_csv(BALANCED_DATA_PATH)
X_balanced = df_balanced.drop(columns=["Label", "Attack_Type"], errors='ignore')

# **Preprocess dataset function**
def preprocess_dataset(df, dataset_name):
    """Ensure the dataset matches training features."""
    print(f"\n🔄 Preprocessing {dataset_name}...")

    # Drop 'Label' and 'Attack_Type' if they exist
    df.drop(columns=["Label", "Attack_Type"], errors='ignore', inplace=True)

    # Handle missing values
    df.fillna(0, inplace=True)

    # Identify missing and extra features
    missing_features = set(X_balanced.columns) - set(df.columns)
    extra_features = set(df.columns) - set(X_balanced.columns)

    # Drop extra features
    if extra_features:
        print(f"⚠️ Warning: Dropping unexpected features {extra_features}")
        df.drop(columns=extra_features, inplace=True)

    # Add missing features with default values (0)
    for feature in missing_features:
        print(f"⚠️ Warning: Adding missing feature {feature} with default value 0")
        df[feature] = 0

    # Ensure the column order matches the training dataset
    df = df[X_balanced.columns]

    # Print feature values (no scaling applied)
    print("\n📊 Sample feature values (NO SCALING APPLIED):")
    print(df.head())

    return df  # Return raw data (no scaling)

# Preprocess both datasets
df_live = preprocess_dataset(pd.read_csv(LIVE_DATA_PATH), "Live Dataset")
df_balanced = preprocess_dataset(pd.read_csv(BALANCED_DATA_PATH), "Balanced Dataset")

# Ensure at least one dataset is valid before continuing
if df_live is None and df_balanced is None:
    print("❌ No valid data to process. Exiting...")
    exit(1)

# Load trained models
model_files = {
    "random_forest": os.path.join(BASE_DIR, "models", "random_forest.pkl"),
    "xgboost": os.path.join(BASE_DIR, "models", "xgboost.pkl"),
    "mlp": os.path.join(BASE_DIR, "models", "mlp.pkl"),
    "ensemble": os.path.join(BASE_DIR, "models", "ensemble.pkl"),
    "pa_model": os.path.join(BASE_DIR, "models", "pa_model.pkl"),  # Incremental learning
    "sgd_model": os.path.join(BASE_DIR, "models", "sgd_model.pkl")  # Incremental learning
}

models = {}
for name, path in model_files.items():
    if os.path.exists(path):
        models[name] = joblib.load(path)
    else:
        print(f"❌ Error: Model file {path} not found! Skipping {name}")

# Ensure we have models to test
if not models:
    print("❌ No models available for prediction. Exiting...")
    exit(1)

# Hardcoded label mapping
label_mapping = {
    "0": "Benign", "1": "DNS", "2": "LDAP", "3": "MSSQL", "4": "NTP",
    "5": "NetBIOS", "6": "Portmap", "7": "SNMP", "8": "Syn", "9": "TFTP",
    "10": "UDP", "11": "UDP-lag", "12": "WebDDoS"
}
reverse_label_mapping = {int(k): v for k, v in label_mapping.items()}

# Function to test dataset on models
def test_models(X, dataset_name):
    """Runs predictions on a dataset using all models and displays the first 5 attack predictions."""
    print(f"\n🔍 Testing models on {dataset_name}:")
    predictions_dict = {}

    for name, model in models.items():
        print(f"\n🧠 Model: {name}")

        try:
            if hasattr(model, "predict_proba"):
                probabilities = model.predict_proba(X)
                print(f"\n📊 First 5 probability scores from {name}:")
                print(probabilities[:5])

                # Adjust threshold dynamically (90th percentile)
                threshold = np.percentile(probabilities[:, 1], 90)
                predictions = (probabilities[:, 1] > threshold).astype(int)
            else:
                predictions = model.predict(X)

            # Decode predictions
            decoded_predictions = [reverse_label_mapping.get(pred, "Unknown") for pred in predictions]

            # Filter for attack predictions (non-"Benign")
            attack_predictions = [pred for pred in decoded_predictions if pred != "Benign"]

            # Display the first 5 attack predictions
            if attack_predictions:
                print(f"📊 First 5 attack predictions: {attack_predictions[:5]}")
            else:
                print("📊 No attack predictions found.")

            if any(pred != "Benign" for pred in decoded_predictions):
                print(f"🚨 Attack detected by {name} on {dataset_name}!")
            else:
                print(f"✅ No attacks detected by {name} on {dataset_name}.")

            predictions_dict[name] = decoded_predictions
        except Exception as e:
            print(f"❌ Error while predicting with {name} on {dataset_name}: {e}")
            predictions_dict[name] = None

    return predictions_dict

# Run predictions on both datasets
live_predictions = test_models(df_live, "Live Dataset") if df_live is not None else None
balanced_predictions = test_models(df_balanced, "Balanced Dataset") if df_balanced is not None else None

# Retrain incremental learning models with new Live Data
if live_predictions is not None:
    incremental_models = ["pa_model", "sgd_model"]
    for model_name in incremental_models:
        if model_name in models:
            print(f"\n🛠️ Updating {model_name} with new live data...")
            new_features = df_live
            new_labels = (df_live["Flow Packets/s"] > df_live["Flow Packets/s"].median()).astype(int)  # Adjust attack labeling

            models[model_name].partial_fit(new_features, new_labels, classes=[0, 1])
            joblib.dump(models[model_name], os.path.join(BASE_DIR, f"models/{model_name}.pkl"))
            print(f"✅ {model_name} updated successfully!")

# Save predictions to CSV
def save_predictions(df, predictions, dataset_name, file_name):
    if predictions is not None:
        if len(df) != len(predictions["random_forest"]):
            print(f"❌ Mismatch: {dataset_name} has {len(df)} rows, but predictions have {len(predictions['random_forest'])} rows!")
            df = df.iloc[:len(predictions["random_forest"])]  # Fix length mismatch
        
        df["Predictions"] = predictions["random_forest"]  # Use RF predictions for consistency
        df.to_csv(os.path.join(BASE_DIR, "data", file_name), index=False)
        print(f"\n✅ Predictions saved to 'data/{file_name}'.")

# Save predictions
save_predictions(df_live, live_predictions, "Live Dataset", "live_predictions.csv")
save_predictions(df_balanced, balanced_predictions, "Balanced Dataset", "balanced_predictions.csv")