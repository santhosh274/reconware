import joblib
import pandas as pd

MODEL_PATH = "../model/random_forest.pkl"
model = joblib.load(MODEL_PATH)
FEATURES = model.feature_names_in_

def ml_predict(entropy):
    # Minimal feature mapping (safe for demo)
    sample = {f: 0 for f in FEATURES}
    if "ResourceSize" in sample:
        sample["ResourceSize"] = entropy * 1000

    df = pd.DataFrame([sample])
    pred = model.predict(df)[0]
    return "Ransomware" if pred == 0 else "Benign"
