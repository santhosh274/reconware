import os
import joblib
import shutil
from pathlib import Path
import numpy as np

# Add backend to path for imports
import sys
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from scanner.feature_extractor import extract_features

# Model paths - try multiple locations
MODEL_PATHS = [
    "backend/scanner/ransomware_model.pkl",
    "model/random_forest.pkl"
]

# Load model from first available path
MODEL = None
for model_path in MODEL_PATHS:
    if os.path.exists(model_path):
        MODEL = joblib.load(model_path)
        print(f"Model loaded from {model_path}")
        break

if MODEL is None:
    raise FileNotFoundError("Model not found in any of these locations: " + ", ".join(MODEL_PATHS))

# Get expected number of features
N_FEATURES = MODEL.n_features_in_
print(f"Model expects {N_FEATURES} features")

# Quarantine folder
QUARANTINE_FOLDER = "backend/quarantine"


def scan_file(file_path):
    """Scan a single file for ransomware indicators."""
    features = extract_features(file_path)

    # Handle feature vector based on model's expected input
    if N_FEATURES == 14:
        # Model expects 14 PE features - use entropy as primary indicator
        ml_features = np.zeros((1, N_FEATURES))
        ml_features[0][0] = features[0]  # Use entropy as primary feature
    else:
        # Model expects different number of features
        ml_features = [features]

    prediction = MODEL.predict(ml_features)[0]
    probability = MODEL.predict_proba(ml_features)[0][1]

    risk = round(float(probability) * 100, 2)

    status = "SAFE"

    if risk > 70:
        status = "RANSOMWARE"
        quarantine(file_path)

    elif risk > 40:
        status = "SUSPICIOUS"

    return {
        "file": file_path,
        "risk": risk,
        "status": status
    }


def quarantine(file_path):
    """Move a file to quarantine directory."""
    if not os.path.exists(QUARANTINE_FOLDER):
        os.makedirs(QUARANTINE_FOLDER)

    filename = os.path.basename(file_path)

    dest = os.path.join(QUARANTINE_FOLDER, filename)

    # Handle filename conflicts
    counter = 1
    base_name, ext = os.path.splitext(filename)
    while os.path.exists(dest):
        dest = os.path.join(QUARANTINE_FOLDER, f"{base_name}_{counter}{ext}")
        counter += 1

    shutil.move(file_path, dest)

    print(f"File quarantined: {filename} -> {dest}")
