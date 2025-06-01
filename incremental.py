import pandas as pd
import numpy as np
import json
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import PassiveAggressiveClassifier, SGDClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.inspection import permutation_importance

# Load dataset
df = pd.read_csv("data/balanced_dataset.csv")

# Load label mapping
with open("label_mapping.json", "r") as f:
    label_mapping = json.load(f)

# Ensure 'Label' column exists
if "Label" not in df.columns:
    raise KeyError("The dataset does not contain a 'Label' column.")

# Convert 'Label' column to integer (0: Benign, 1: Attack)
if not np.issubdtype(df["Label"].dtype, np.number):
    reverse_label_mapping = {v: int(k) for k, v in label_mapping.items()}
    df["Label"] = df["Label"].astype(str).map(reverse_label_mapping)

# Ensure binary classification (0 for benign, 1 for attack)
df["Label"] = df["Label"].apply(lambda x: 1 if x != 0 else 0)

# Fill NaN values in Label column with 0
df["Label"].fillna(0, inplace=True)
df["Label"] = df["Label"].astype(int)

# Extract features and target
features_to_drop = ["Label"]
if "Attack_Type" in df.columns:
    features_to_drop.append("Attack_Type")

X = df.drop(columns=features_to_drop)
y = df["Label"]

# Fill NaN values in features with 0
X.fillna(0, inplace=True)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Normalize features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Convert X_train and X_test back to DataFrames with feature names
X_train = pd.DataFrame(X_train, columns=X.columns)  # Ensure feature names are preserved
X_test = pd.DataFrame(X_test, columns=X.columns)    # Ensure feature names are preserved

# Initialize models with tuned hyperparameters
pa_model = PassiveAggressiveClassifier(max_iter=1000, C=0.5, random_state=42)
sgd_model = SGDClassifier(loss="log_loss", alpha=0.0001, max_iter=1000, random_state=42)

# Train models
pa_model.fit(X_train, y_train)
sgd_model.fit(X_train, y_train)

# Function to adjust decision threshold for linear models
def adjust_threshold(model, X_test, threshold=0.3):
    if hasattr(model, "decision_function"):
        y_probs = model.decision_function(X_test)
    else:
        y_probs = model.predict_proba(X_test)[:, 1]  # Use probability if available
    return (y_probs > threshold).astype(int)

# Adjust threshold and get predictions
y_pred_pa = adjust_threshold(pa_model, X_test, threshold=0.3)
y_pred_sgd = adjust_threshold(sgd_model, X_test, threshold=0.3)

# Function to evaluate models and compute feature importance
def evaluate_model(y_true, y_pred, model, model_name):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    # Feature Importance using Permutation Importance
    importance = permutation_importance(model, X_test, y_test, scoring="recall", random_state=42)
    feature_importances = pd.DataFrame({"Feature": X.columns, "Importance": importance.importances_mean})
    feature_importances = feature_importances.sort_values(by="Importance", ascending=False)

    # Save evaluation results
    with open(f"{model_name}_evaluation.txt", "w") as f:
        f.write(f"Model: {model_name}\n")
        f.write(f"Accuracy: {accuracy:.4f}\n")
        f.write(f"Precision: {precision:.4f}\n")
        f.write(f"Recall: {recall:.4f}\n")
        f.write(f"F1 Score: {f1:.4f}\n")
        f.write("\nFeature Importance (Top 10 Features):\n")
        f.write(feature_importances.head(10).to_string(index=False))

    print(f"{model_name} - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, "
          f"F1: {f1:.4f}")

    return accuracy, precision, recall, f1, feature_importances

# ✅ Corrected variable unpacking
metrics_pa = evaluate_model(y_test, y_pred_pa, pa_model, "PassiveAggressive")
metrics_sgd = evaluate_model(y_test, y_pred_sgd, sgd_model, "SGDClassifier")

# Save models and scaler
joblib.dump(pa_model, "pa_model.pkl")
joblib.dump(sgd_model, "sgd_model.pkl")
joblib.dump(scaler, "scaler.pkl")

print("Models and scaler saved successfully.")

# Extract values for plotting
metric_labels = ["Accuracy", "Precision", "Recall", "F1 Score"]
pa_values = metrics_pa[:4]  # First four elements are accuracy, precision, recall, f1
sgd_values = metrics_sgd[:4]

x = np.arange(len(metric_labels))
width = 0.3

# Create a comparison plot
fig, ax = plt.subplots(figsize=(10, 5))
rects1 = ax.bar(x - width/2, pa_values, width, label="PassiveAggressive", color="royalblue")
rects2 = ax.bar(x + width/2, sgd_values, width, label="SGDClassifier", color="orange")

ax.set_xlabel("Metrics")
ax.set_ylabel("Score")
ax.set_title("Comparison of Model Performance")
ax.set_xticks(x)
ax.set_xticklabels(metric_labels)
ax.legend()

for rect in rects1 + rects2:
    height = rect.get_height()
    ax.annotate(f'{height:.3f}', xy=(rect.get_x() + rect.get_width() / 2, height),
                xytext=(0, 5), textcoords="offset points",
                ha="center", va="bottom")

plt.savefig("model_comparison.png")
plt.show()

print("Comparison plot saved as 'model_comparison_incremental.png'.")

# Extract feature importance
feature_importance_pa = metrics_pa[4]  # Last element is feature importance DataFrame
feature_importance_sgd = metrics_sgd[4]

# Plot Feature Importance
fig, ax = plt.subplots(1, 2, figsize=(15, 5))

sns.barplot(y=feature_importance_pa["Feature"][:10], x=feature_importance_pa["Importance"][:10], ax=ax[0], color="royalblue")
ax[0].set_title("Feature Importance - PassiveAggressive")
ax[0].set_xlabel("Importance")
ax[0].set_ylabel("Feature")

sns.barplot(y=feature_importance_sgd["Feature"][:10], x=feature_importance_sgd["Importance"][:10], ax=ax[1], color="orange")
ax[1].set_title("Feature Importance - SGDClassifier")
ax[1].set_xlabel("Importance")
ax[1].set_ylabel("Feature")

plt.tight_layout()
plt.savefig("feature_importance_incremental.png")
plt.show()

print("Feature importance plot saved as 'feature_importance.png'.")