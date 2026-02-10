import os
import json
import joblib
import warnings
import numpy as np
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Query, HTTPException

# Internal module imports
from scanner.folder_scanner import scan_folder
from prevention.process_killer import kill_process_by_path
from prevention.locker import lock_file
from prevention.quarantine import quarantine
from utils.results_loader import load_results

# Suppress model version warnings
warnings.filterwarnings("ignore", category=UserWarning)

app = FastAPI(title="Ransomware Detection API")

# --- CORS Configuration ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configuration & Paths ---
BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
RESULTS_FILE = STORAGE_DIR / "results.json"
MODEL_PATH = BASE_DIR.parent / "model" / "random_forest.pkl"

# Ensure storage directory exists
STORAGE_DIR.mkdir(exist_ok=True)

# --- Load Model at Startup ---
model = None
if MODEL_PATH.exists():
    try:
        model = joblib.load(MODEL_PATH)
        print(f"✅ Model loaded successfully from {MODEL_PATH}")
    except Exception as e:
        print(f"❌ Error loading model: {e}")
else:
    print(f"❌ Critical Error: Model not found at {MODEL_PATH}")

@app.post("/scan")
def scan(path: str = Query(...)):
    if model is None:
        raise HTTPException(status_code=500, detail="ML Model not loaded on server.")

    try:
        # 1. Perform the physical folder scan
        # This assumes scan_folder returns a list of dicts with 'file', 'path', 'entropy'
        scanned_items = scan_folder(path)
        final_results = []

        # 2. Process each file through the ML model
        for item in scanned_items:
            entropy = item.get("entropy", 0.0)
            file_path = item.get("path")
            
            # Prepare features (assuming model expects [entropy, ...others])
            # We fill other features with 0 if only entropy is available from the scanner
            feature_count = model.n_features_in_
            features = np.zeros((1, feature_count))
            features[0][0] = entropy 

            # Predict (1 = Ransomware, 0 = Benign)
            prediction = model.predict(features)[0]

            status = "Benign"
            action = "None"

            # 3. Detection & Prevention Logic
            # High entropy (> 7.5) + ML model prediction of 1
            if entropy > 7.5 and prediction == 1:
                kill_process_by_path(file_path)
                lock_file(file_path)
                quarantine(file_path)
                status = "Ransomware"
                action = "Blocked/Quarantined"

            final_results.append({
                "file": item.get("file"),
                "path": file_path,
                "entropy": round(entropy, 4),
                "status": status,
                "action": action
            })

        # 4. Save results to JSON for the frontend to fetch
        with open(RESULTS_FILE, "w") as f:
            json.dump(final_results, f, indent=2)

        return {"status": "success", "count": len(final_results), "data": final_results}

    except Exception as e:
        print(f"SCAN ERROR: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/results")
def get_results():
    """
    Returns the latest scan results stored in results.json
    """
    try:
        # Using your existing utility loader
        return load_results()
    except Exception as e:
        return {"error": "Could not load results", "details": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)