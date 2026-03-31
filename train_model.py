import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# Define paths - use relative paths from project root
DATA_PATH = "ransomware_processed.csv"
MODEL_OUTPUT_PATH = "backend/scanner/ransomware_model.pkl"

# Also save a copy in the model folder for compatibility
MODEL_COPY_PATH = "model/random_forest.pkl"

# Load data
print(f"Loading data from {DATA_PATH}...")
data = pd.read_csv(DATA_PATH)

# The original model was trained with 14 PE features
# For the new entropy-based detection, we use 5 features:
# entropy, crypto_api_hits, file_api_hits, ransom_keyword_hits, file_size
# 
# Since the original CSV has PE features, we need to either:
# 1. Use the existing model with appropriate feature mapping
# 2. Create synthetic training data for the 5-feature model
#
# For now, let's train a model with the available features and map appropriately

# Get feature columns (excluding label)
feature_cols = [col for col in data.columns if col != 'label']
print(f"Available features: {feature_cols}")
print(f"Total features: {len(feature_cols)}")

# Use all available features for training
X = data.drop("label", axis=1)
y = data["label"]

print(f"Training on {len(X)} samples with {X.shape[1]} features...")

# Train model
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=12
)

model.fit(X, y)

# Ensure output directories exist
os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)
os.makedirs(os.path.dirname(MODEL_COPY_PATH), exist_ok=True)

# Save model to primary location
joblib.dump(model, MODEL_OUTPUT_PATH)
print(f"Model saved to {MODEL_OUTPUT_PATH}")

# Also save copy to model folder
joblib.dump(model, MODEL_COPY_PATH)
print(f"Model copy saved to {MODEL_COPY_PATH}")

print("Model training complete!")
print(f"Model expects {model.n_features_in_} features: {model.feature_names_in_.tolist()}")
