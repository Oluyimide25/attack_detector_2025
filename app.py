import os
import joblib
import pandas as pd
import numpy as np
from flask import Flask
from dash import Dash, dcc, html, Input, Output
import plotly.express as px
import logging
import warnings
from sklearn.exceptions import InconsistentVersionWarning
from sklearn.preprocessing import StandardScaler

# Suppress scikit-learn version mismatch warnings
warnings.simplefilter("ignore", InconsistentVersionWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Create Flask app
app = Flask(__name__)

# Create Dash app and link it to Flask
dash_app = Dash(__name__, server=app, routes_pathname_prefix="/dashboard/")

# Define Dash layout with styling and your name as a subheading
dash_app.layout = html.Div(style={'backgroundColor': '#f4f4f4', 'padding': '20px'}, children=[
    html.H1("Real-Time DDoS Attack Detection System", style={'color': '#333', 'textAlign': 'center'}),
    html.H3("by Onaolapo Oluyimide", style={'color': '#555', 'textAlign': 'center'}),  # Added your name
    dcc.Interval(id="update-interval", interval=5000, n_intervals=0),
    html.Div(id="live-predictions", style={'marginTop': '20px', 'fontSize': '18px'}),
    dcc.Graph(id="attack-trends", style={'marginTop': '20px'}),
    html.Div(id="flagged-ips", style={'marginTop': '20px', 'fontSize': '18px'})
])

# Load trained models using joblib
model_paths = {
    "xgboost": "models/xgboost.pkl",
    "sgd": "models/sgd_model.pkl",
    "passive_aggressive": "models/pa_model.pkl"
}

models = {}
for model_name, path in model_paths.items():
    try:
        models[model_name] = joblib.load(path)
        logging.info(f"✅ Successfully loaded {model_name} model.")
    except Exception as e:
        logging.error(f"❌ Failed to load {model_name}: {e}")
        models[model_name] = None

# Ensure that all models loaded correctly
loaded_models = {k: v for k, v in models.items() if v is not None}
logging.info(f"✅ Loaded models: {list(loaded_models.keys())}")

# If critical models are missing, exit
if len(loaded_models) < 3:
    logging.error("❌ Critical models failed to load. Check model files and versions.")
    exit(1)

# Load scaler for normalization
try:
    scaler = joblib.load("models/scaler.pkl")

    # Ensure the scaler is a valid StandardScaler instance
    if not isinstance(scaler, StandardScaler):
        raise ValueError("❌ Loaded scaler is not a StandardScaler instance.")

    logging.info("✅ Successfully loaded scaler.")
except Exception as e:
    logging.error(f"❌ Error loading scaler: {e}. Please run `save_scaler.py` to generate a valid scaler.")
    exit(1)

# Define columns to keep
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

# Ensure the 'data' directory exists
os.makedirs("data", exist_ok=True)
LIVE_DATA_PATH = "data/live_network_data.csv"

# Create placeholder CSV if it doesn't exist
if not os.path.exists(LIVE_DATA_PATH):
    placeholder_data = pd.DataFrame(columns=FEATURE_COLUMNS + ["Source IP"])
    placeholder_data.to_csv(LIVE_DATA_PATH, index=False)
    logging.info("✅ Created placeholder CSV for live network data.")

# Read live network data and preprocess
def preprocess_live_data():
    if not os.path.exists(LIVE_DATA_PATH):
        raise FileNotFoundError(f"Live data file '{LIVE_DATA_PATH}' not found.")

    df = pd.read_csv(LIVE_DATA_PATH, low_memory=False)

    # Ensure all required features exist
    missing_features = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_features:
        logging.warning(f"⚠️ Missing features: {missing_features}")
        df = df.reindex(columns=FEATURE_COLUMNS + ["Source IP"], fill_value=0)  # Fill missing columns with zeros

    # Select relevant columns
    df_features = df[FEATURE_COLUMNS]
    df_source_ip = df["Source IP"]

    # Convert all columns to numeric, coercing errors (non-numeric values become NaN)
    df_features = df_features.apply(pd.to_numeric, errors='coerce')

    # Ensure the dataset has no missing values
    df_features.fillna(df_features.median(numeric_only=True), inplace=True)

    # Convert numpy-specific types to standard Python types
    df_features = df_features.astype(float)

    # Normalize using the scaler
    try:
        df_scaled = scaler.transform(df_features)
        df_scaled = pd.DataFrame(df_scaled, columns=FEATURE_COLUMNS)
    except Exception as e:
        logging.error(f"❌ Scaling error: {e}. Check if `scaler.pkl` matches `live_network_data.csv`.")
        return pd.DataFrame(), pd.Series()  # Return empty DataFrame and Series to prevent crashes

    logging.info("✅ Successfully preprocessed live data.")
    logging.info(f"📊 Preprocessed data shape: {df_scaled.shape}")
    logging.info(f"📊 Sample preprocessed data:\n{df_scaled.head()}")
    return df_scaled, df_source_ip

# Make predictions using XGBoost and update SGD and PA models
def predict_and_update(X_live):
    # Use XGBoost for predictions
    xgboost_predictions = models["xgboost"].predict(X_live)

    # Convert multi-class predictions to binary (attack vs. benign)
    binary_predictions = np.where(xgboost_predictions == 0, 0, 1)  # 0 = Benign, 1 = Attack

    # Update SGD and PA models with binary predictions
    models["sgd"].partial_fit(X_live, binary_predictions, classes=[0, 1])
    models["passive_aggressive"].partial_fit(X_live, binary_predictions, classes=[0, 1])

    return binary_predictions

# Define Dash callback
@dash_app.callback(
    [Output("live-predictions", "children"), Output("attack-trends", "figure"), Output("flagged-ips", "children")],
    [Input("update-interval", "n_intervals")],
    prevent_initial_call=True
)
def update_dashboard(_):
    try:
        preprocessed_data, source_ips = preprocess_live_data()
        if preprocessed_data.empty:
            logging.warning("⚠️ No valid data to predict on. Skipping this update.")
            return html.H3("⚠️ No data available."), px.bar(title="No Data"), html.Div()

        logging.info(f"📊 Preprocessed data shape: {preprocessed_data.shape}")

        # Make predictions and update models
        predictions = predict_and_update(preprocessed_data)
        predictions = np.ravel(predictions)

        if predictions.size == 0:
            logging.warning("⚠️ No predictions generated. Data might be empty.")
            return html.H3("⚠️ No predictions available."), px.bar(title="No Predictions"), html.Div()

        # Count the number of attacks and benign traffic
        num_attacks = np.sum(predictions == 1)  # 1 = Attack
        num_benign = np.sum(predictions == 0)  # 0 = Benign
        ATTACK_THRESHOLD = 200  # Adjusted to reduce false positives

        if num_attacks >= ATTACK_THRESHOLD:
            prediction_text = f"🚨 DDoS Attack Detected! ({num_attacks} attacks, {num_benign} benign)"
        else:
            prediction_text = f"✅ Normal Traffic ({num_attacks} attacks, {num_benign} benign)"

        # Create a DataFrame for the graph
        attack_counts = pd.DataFrame({
            "Traffic Type": ["Attacks", "Benign"],
            "Count": [num_attacks, num_benign]
        })

        # Create the bar plot
        fig = px.bar(attack_counts, x="Traffic Type", y="Count", title="Live Attack Trends",
                     labels={"Count": "Number of Instances", "Traffic Type": "Traffic Type"},
                     color="Traffic Type", color_discrete_map={"Attacks": "red", "Benign": "green"})

        # Get the last 10 flagged IPs
        flagged_ips = source_ips[predictions == 1].tail(10)
        flagged_ips_list = flagged_ips.tolist()
        flagged_ips_text = "Last 10 Flagged IPs: " + ", ".join(flagged_ips_list)

        return html.H3(f"Status: {prediction_text}"), fig, html.Div(flagged_ips_text)

    except Exception as e:
        logging.error(f"❌ Error updating dashboard: {e}")
        return html.H3("Error updating dashboard."), px.bar(title="Error updating dashboard"), html.Div()

# Home route - Redirect to the dashboard
@app.route("/")
def home():
    return dash_app.index()  # Make the dashboard the home page

# Run the app
if __name__ == "__main__":
    app.run(debug=True)