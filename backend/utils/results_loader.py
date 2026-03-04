# utils/results_loader.py
import json
from pathlib import Path

RESULTS_FILE = Path(__file__).parent.parent / "storage" / "results.json"

def load_results():
    if not RESULTS_FILE.exists():
        return {"timestamp": None, "files": []}
    
    with open(RESULTS_FILE, "r") as f:
        data = json.load(f)
    
    print("DEBUG - Raw data from results.json:", data)  # Add this for debugging
    
    # If data is a list (old format), wrap it
    if isinstance(data, list):
        return {"timestamp": None, "files": data}
    
    return data