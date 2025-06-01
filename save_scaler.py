import os
import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler

SCALER_PATH = "models/scaler.pkl"
DATASET_PATH = "data/balanced_dataset.csv"

# Delete the existing scaler if it exists
if os.path.exists(SCALER_PATH):
    os.remove(SCALER_PATH)
    print("✅ Deleted old scaler.pkl")

# Load dataset
df_train = pd.read_csv(DATASET_PATH)

# Select only numeric columns
X_train = df_train.select_dtypes(include=['number'])

# Drop target columns if they exist
X_train = X_train.drop(columns=["Label", "Attack_Type"], errors="ignore")

# Fit and save new scaler
scaler = StandardScaler()
scaler.fit(X_train)

# Confirm scaler is fitted
assert hasattr(scaler, "mean_"), "❌ Scaler was not properly fitted!"

# Save it
joblib.dump(scaler, SCALER_PATH)
print("✅ New StandardScaler instance saved.")
