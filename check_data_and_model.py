import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# 🔹 Load your datasets (replace with actual file paths)
train_data_path = "data/balanced_dataset.csv"
live_data_path = "data/live_network_data.csv"

# 🔹 Load Data
df_train = pd.read_csv(train_data_path)
df_live = pd.read_csv(live_data_path)

# 🔍 Confirm available columns
print("\n📝 Train Data Columns:", df_train.columns.tolist())
print("📝 Live Data Columns:", df_live.columns.tolist())

# 🔹 Identify the correct label column
label_col = "Label" if "Label" in df_train.columns else "Attack_Type"

# 🔹 Features & Labels
X_train = df_train.drop(columns=[label_col], errors='ignore')  
y_train = df_train[label_col]

X_live = df_live.drop(columns=[label_col], errors='ignore') if label_col in df_live.columns else df_live.copy()
y_live = df_live[label_col] if label_col in df_live.columns else None

# ✅ 1️⃣ Check for Missing or Invalid Values
if np.any(pd.isna(X_train)) or np.any(np.isinf(X_train)):
    print("🚨 X_train contains NaN or infinite values. Cleaning data...")
    X_train = X_train.fillna(X_train.mean())
    X_train = X_train.replace([np.inf, -np.inf], X_train.mean())

if np.any(pd.isna(X_live)) or np.any(np.isinf(X_live)):
    print("🚨 X_live contains NaN or infinite values. Cleaning data...")
    X_live = X_live.fillna(X_live.mean())
    X_live = X_live.replace([np.inf, -np.inf], X_live.mean())

# ✅ 2️⃣ Ensure 'Attack_Type' and 'Label' Are Not in Features
X_train = X_train.drop(columns=['Attack_Type', 'Label'], errors='ignore')
X_live = X_live.drop(columns=['Attack_Type', 'Label'], errors='ignore')

# ✅ 3️⃣ Check Feature Presence & Align Features
missing_features = set(X_train.columns) - set(X_live.columns)
extra_features = set(X_live.columns) - set(X_train.columns)

if missing_features:
    print(f"🚨 Missing features in live data: {missing_features}")
    for col in missing_features:
        X_live[col] = 0  # Add missing features with neutral values

if extra_features:
    print(f"⚠️ Extra features in live data: {extra_features}")
    X_live = X_live.drop(columns=extra_features)  # Drop extra features

# ✅ 4️⃣ Check Feature Distribution
print("\n🔍 Feature Distribution (Train vs. Live)")
print(X_train.describe().T.join(X_live.describe().T, lsuffix='_train', rsuffix='_live'))

# ✅ 5️⃣ Apply Standard Scaling
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_live_scaled = scaler.transform(X_live)

# ✅ 6️⃣ Train Random Forest Model
rf = RandomForestClassifier(n_estimators=100, max_depth=10, min_samples_split=5, random_state=42)
rf.fit(X_train_scaled, y_train)

# 🔹 Predict on live data
rf_probs = rf.predict_proba(X_live_scaled)[:, 1]
rf_preds = (rf_probs > 0.5).astype(int)

# 🔹 Test Lower Thresholds
for threshold in [0.5, 0.3, 0.1]:
    preds = (rf_probs > threshold).astype(int)
    print(f"\n📊 RF Prediction Summary at Threshold {threshold}:")
    print(pd.Series(preds).value_counts())

# ✅ 7️⃣ Evaluate Model (if labels exist in live data)
if y_live is not None:
    print("\n📢 Classification Report (Random Forest - Default Threshold 0.5):")
    print(classification_report(y_live, rf_preds))
else:
    print("\n⚠️ No labels in live data; skipping evaluation.")

print("\n✅ Check Complete!")