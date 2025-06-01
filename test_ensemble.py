import joblib
import pandas as pd
import logging
from sklearn.preprocessing import StandardScaler

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Model file paths
model_paths = {
    "MLP": "models/mlp.pkl",
    "PassiveAggressive": "models/pa_model.pkl",
    "RandomForest": "models/random_forest.pkl",
    "SGD": "models/sgd_model.pkl",
    "XGBoost": "models/xgboost.pkl"
}

# Load trained scaler
scaler = joblib.load("models/scaler.pkl")  # Ensure the scaler was saved during training

# Load a trained model to get expected feature names
sample_model = joblib.load(list(model_paths.values())[0])  
trained_feature_names = sample_model.feature_names_in_  # Expected feature order

# Label mapping (Benign = 0, All others = Attacks)
attack_labels = set(range(1, 13))  # All labels 1-12 are attacks

# Load datasets
datasets = {
    "Balanced Dataset": "data/balanced_dataset.csv",
    "Live Network Data": "data/live_network_data.csv"
}

for dataset_name, dataset_path in datasets.items():
    logging.info(f"\n🔍 Testing on: {dataset_name} 🔍")

    # Load dataset
    df = pd.read_csv(dataset_path)
    logging.info(f"Data loaded. Shape: {df.shape}")

    # Ensure correct feature columns (drop labels if present)
    X = df.drop(columns=["Label", "Attack_Type"], errors="ignore")

    # Reorder test dataset to match training order
    X = X.reindex(columns=trained_feature_names, fill_value=0)  

    # Apply the same preprocessing as training
    X_preprocessed = scaler.transform(X)

    # Test each model
    for model_name, model_path in model_paths.items():
        logging.info(f"Loading model: {model_name}...")
        model = joblib.load(model_path)

        # Ensure feature names are retained before prediction
        X_test = pd.DataFrame(X_preprocessed, columns=trained_feature_names)

        logging.info(f"Making predictions with {model_name}...")
        predictions = model.predict(X_test)

        # Post-processing: Count attacks (everything except '0')
        attack_count = sum(pred in attack_labels for pred in predictions)
        normal_count = sum(pred == 0 for pred in predictions)

        logging.info(f"{model_name} - {dataset_name} Prediction Summary: {attack_count} Attacks, {normal_count} Normal")

logging.info("✅ Testing completed!")
