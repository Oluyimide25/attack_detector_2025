import joblib
import pandas as pd
import logging
from sklearn.ensemble import VotingClassifier

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load and preprocess training data
logging.info("Loading training data...")
df_train = pd.read_csv("data/balanced_dataset.csv")
X_train = df_train.drop(columns=["Label", "Attack_Type"], errors="ignore")
y_train = df_train["Label"]
logging.info(f"Training data loaded. Shape: {X_train.shape}")

# Load pre-trained models
logging.info("Loading pre-trained models...")
models = {
    "random_forest": joblib.load("models/random_forest.pkl"),
    "xgboost": joblib.load("models/xgboost.pkl"),
}

logging.info("Models loaded successfully!")

# Define ensemble model
logging.info("Initializing Voting Classifier...")
ensemble_model = VotingClassifier(estimators=[
    ("random_forest", models["random_forest"]),
    ("xgboost", models["xgboost"]),
], voting="hard")  # Change to 'soft' if you want probability-based voting

# Train the ensemble model (this step is optional if models are pre-trained)
logging.info("Training the ensemble model...")
ensemble_model.fit(X_train, y_train)
logging.info("Ensemble model training complete!")

# Save the trained ensemble model
logging.info("Saving the ensemble model...")
joblib.dump(ensemble_model, "models/ensemble.pkl")
logging.info("✅ Ensemble model saved successfully!")
