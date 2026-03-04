import os
import json
import time
import joblib
import warnings
import traceback
import numpy as np
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from watchdog.observers import Observer

# Internal modules
from scanner.folder_scanner import scan_folder
from prevention.process_killer import kill_process_by_path, kill_process_by_name, kill_ransomware_processes
from prevention.locker import lock_file
from prevention.quarantine import quarantine_file, restore_file, list_quarantined_files, QUARANTINE_DIR
from utils.results_loader import load_results
from monitor import RansomwareEventHandler, set_model
from detection.content_analyzer import ContentAnalyzer
from scanner.entropy import calculate_entropy

warnings.filterwarnings("ignore", category=UserWarning)

app = FastAPI(title="Ransomware Detection API")

# Custom CORS middleware to ensure headers are properly set
class CustomCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

app.add_middleware(CustomCORSMiddleware)

# Also add the standard CORS middleware as backup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Paths ---
BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
RESULTS_FILE = STORAGE_DIR / "results.json"
MODEL_PATH = BASE_DIR.parent / "model" / "random_forest.pkl"

STORAGE_DIR.mkdir(exist_ok=True)

# --- Load Model ---
model = None
if MODEL_PATH.exists():
    try:
        model = joblib.load(MODEL_PATH)
        print(f"✅ Model loaded from {MODEL_PATH}")
        set_model(model)  # make available to monitor
    except Exception as e:
        print(f"❌ Model load error: {e}")
else:
    print(f"❌ Model not found at {MODEL_PATH}")

# Global observer for real-time monitoring
observer = None


@app.post("/scan")
def start_monitoring(path: str = Query(...)):
    """Start watching a folder for changes."""
    global observer
    if model is None:
        raise HTTPException(500, "ML model not loaded")

    # Basic path validation - decode URL-encoded path for Windows
    decoded_path = Path(path)
    if ".." in path:
        raise HTTPException(400, "Invalid folder path: '..' not allowed")
    
    # Try to resolve the path - handle URL encoding issues
    try:
        # For Windows paths like C%3A%5CUsers... decode properly
        import urllib.parse
        if '%' in path:
            decoded_path = Path(urllib.parse.unquote(path))
        
        if not decoded_path.exists():
            raise HTTPException(400, f"Folder does not exist: {decoded_path}")
        
        if not decoded_path.is_dir():
            raise HTTPException(400, f"Path is not a directory: {decoded_path}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Invalid path: {str(e)}")

    # Stop any previous observer
    if observer and observer.is_alive():
        observer.stop()
        observer.join()

    # --- Initial full scan (populate results with existing files) ---
    scanned_items = []
    try:
        print(f"[API] Starting scan of: {decoded_path}")
        scanned_items = scan_folder(str(decoded_path), model=model)
        print(f"[API] Scan found {len(scanned_items)} files")
        
        # Quarantine any already suspicious files
        for item in scanned_items:
            if item["blocked"]:
                try:
                    quarantine_file(Path(item["full_path"]))
                except Exception as qe:
                    print(f"[API] Quarantine failed for {item['full_path']}: {qe}")
        
        # Write initial results with timestamp
        with open(RESULTS_FILE, "w") as f:
            json.dump({"timestamp": time.time(), "files": scanned_items}, f, indent=2)
            
    except Exception as e:
        error_details = traceback.format_exc()
        print(f"[API] Initial scan failed: {e}")
        print(f"[API] Traceback: {error_details}")
        # Write error info to results but still start monitoring
        with open(RESULTS_FILE, "w") as f:
            json.dump({
                "timestamp": time.time(), 
                "files": scanned_items,
                "error": str(e),
                "error_type": type(e).__name__
            }, f, indent=2)

    # --- Start watchdog observer for real-time monitoring ---
    try:
        event_handler = RansomwareEventHandler(str(decoded_path), RESULTS_FILE)
        observer = Observer()
        observer.schedule(event_handler, str(decoded_path), recursive=True)
        observer.start()
        print(f"[API] Monitoring started for: {decoded_path}")
    except Exception as e:
        error_details = traceback.format_exc()
        print(f"[API] Failed to start watchdog observer: {e}")
        print(f"[API] Traceback: {error_details}")
        raise HTTPException(500, f"Failed to start monitoring: {str(e)}")

    return {
        "status": "monitoring started", 
        "folder": str(decoded_path),
        "scanned_files": len(scanned_items)
    }


@app.get("/results")
def get_results():
    """Return latest scan results."""
    try:
        results = load_results()
        # Log results for debugging
        print(f"[API] Returning {len(results.get('files', []))} scanned files")
        for file in results.get('files', [])[:3]:  # Log first 3 files
            print(f"[API] File: {file.get('filename')} - Risk: {file.get('risk_score', 'N/A')}, Level: {file.get('risk_level', 'N/A')}, Blocked: {file.get('blocked')}")
        return results
    except Exception as e:
        print(f"[API] Error loading results: {e}")
        return {"error": str(e)}


@app.post("/stop")
def stop_monitoring():
    """Stop the current folder watcher."""
    global observer
    if observer and observer.is_alive():
        observer.stop()
        observer.join()
        return {"status": "monitoring stopped"}
    return {"status": "not monitoring"}


@app.post("/rescan")
def force_rescan(path: str = Query(...)):
    """Force a fresh scan with enhanced detection"""
    global observer
    if model is None:
        raise HTTPException(500, "ML model not loaded")
    
    print(f"\n[API] Starting rescan of: {path}")
    
    # Stop monitoring
    if observer and observer.is_alive():
        observer.stop()
        observer.join()
    
    # Clear old results
    if RESULTS_FILE.exists():
        RESULTS_FILE.unlink()
    
    # Run fresh scan with enhanced detection
    print(f"[API] Scanning folder...")
    scanned_items = scan_folder(path, model=model)
    
    # Log scan summary
    blocked_files = [f for f in scanned_items if f.get("blocked")]
    critical_files = [f for f in scanned_items if f.get("risk_level") == "CRITICAL"]
    high_files = [f for f in scanned_items if f.get("risk_level") == "HIGH"]
    
    print(f"\n[API] Scan Complete!")
    print(f"[API] Total files: {len(scanned_items)}")
    print(f"[API] Blocked: {len(blocked_files)}")
    print(f"[API] CRITICAL: {len(critical_files)}")
    print(f"[API] HIGH: {len(high_files)}")
    
    # Log details of critical/high risk files
    for file in critical_files + high_files:
        print(f"[API] >>> {file['filename']} - {file['risk_level']} ({file['risk_score']}%)")
        if file.get('findings'):
            for finding in file['findings'][:2]:  # Show first 2 findings
                print(f"      - {finding['description']}")
    
    # Write new results
    with open(RESULTS_FILE, "w") as f:
        json.dump({"timestamp": time.time(), "files": scanned_items}, f, indent=2)
    
    # Restart monitoring
    event_handler = RansomwareEventHandler(path, RESULTS_FILE)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    
    return {
        "status": "rescan complete", 
        "count": len(scanned_items),
        "blocked": len(blocked_files),
        "critical": len(critical_files),
        "high": len(high_files),
        "sample": scanned_items[0] if scanned_items else None
    }


@app.get("/analyze/{file_path:path}")
def analyze_file(file_path: str):
    """
    Analyze a single file with detailed scoring breakdown.
    Useful for debugging and understanding detection results.
    """
    path = Path(file_path)
    
    if not path.exists():
        raise HTTPException(404, "File not found")
    
    # Calculate entropy
    entropy = calculate_entropy(str(path))
    
    # Run content analysis
    content_analysis = ContentAnalyzer.analyze_file(str(path))
    
    # Get ML prediction if model available
    ml_prediction = "Unknown"
    ml_confidence = 0.0
    
    if model is not None:
        try:
            features = np.zeros((1, model.n_features_in_))
            features[0][0] = entropy
            pred = int(model.predict(features)[0])
            ml_prediction = "Ransomware" if pred == 0 else "Benign"
            
            try:
                proba = model.predict_proba(features)[0]
                ml_confidence = float(max(proba))
            except:
                ml_confidence = 0.8
        except Exception as e:
            ml_prediction = f"Error: {str(e)}"
    
    # Get combined risk score
    if content_analysis.get("risk_score") is not None:
        combined_score, risk_level = ContentAnalyzer.get_combined_risk_score(
            entropy, 
            0 if ml_prediction == "Ransomware" else 1,
            content_analysis
        )
    else:
        combined_score = int(entropy * 10) if entropy > 7 else int(entropy * 5)
        risk_level = ContentAnalyzer._get_risk_level(combined_score)
    
    return {
        "file": str(path),
        "entropy": entropy,
        "ml_prediction": ml_prediction,
        "ml_confidence": round(ml_confidence, 4),
        "content_analysis": content_analysis,
        "combined_risk_score": combined_score,
        "risk_level": risk_level
    }


@app.post("/block")
def block_file(path: str = Query(...)):
    """
    Immediately block (quarantine) a suspicious file.
    """
    file_path = Path(path)
    
    if not file_path.exists():
        raise HTTPException(404, "File not found")
    
    # First try to kill any process using the file
    success, pids, msg = kill_ransomware_processes(str(file_path))
    
    # Then quarantine
    success, msg = quarantine_file(file_path)
    
    if success:
        return {"status": "blocked", "message": msg, "processes_killed": pids}
    else:
        raise HTTPException(500, msg)


@app.get("/quarantine")
def get_quarantine_list():
    """List all quarantined files."""
    return {
        "quarantine_dir": str(QUARANTINE_DIR),
        "files": list_quarantined_files()
    }


@app.post("/quarantine/restore")
def restore_quarantined_file(quarantine_name: str = Query(...), destination: str = Query(...)):
    """Restore a quarantined file."""
    success, msg = restore_file(quarantine_name, Path(destination))
    
    if success:
        return {"status": "restored", "message": msg}
    else:
        raise HTTPException(500, msg)


@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "monitoring_active": observer is not None and observer.is_alive() if observer else False,
        "quarantine_dir": str(QUARANTINE_DIR)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

