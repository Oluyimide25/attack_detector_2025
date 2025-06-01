import joblib
from sklearn.preprocessing import StandardScaler

SCALER_PATH = "models/scaler.pkl"

try:
    # Load the scaler
    scaler = joblib.load(SCALER_PATH)
    
    print(f"✅ Loaded scaler: {type(scaler)}")
    print(f"✅ Is instance of StandardScaler: {isinstance(scaler, StandardScaler)}")

    if hasattr(scaler, "mean_"):
        print("✅ Scaler is properly fitted.")
    else:
        print("❌ Scaler is NOT fitted.")

except Exception as e:
    print(f"❌ Error loading scaler: {e}")
