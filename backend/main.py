import os
import json
import time
import joblib
import warnings
import traceback
import numpy as np
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Query, HTTPException, Request, Body
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from watchdog.observers import Observer

# Internal modules
from scanner.folder_scanner import scan_folder
from prevention.process_killer import kill_process_by_path, kill_process_by_name, kill_ransomware_processes
from prevention.locker import lock_file
from prevention.quarantine import quarantine_file, restore_file, list_quarantined_files, QUARANTINE_DIR
from utils.results_loader import load_results
from monitor import RansomwareEventHandler, set_model, init_canaries
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
        print(f"[OK] Model loaded from {MODEL_PATH}")
        set_model(model)  # make available to monitor
    except Exception as e:
        print(f"[ERROR] Model load error: {e}")
else:
    print(f"[ERROR] Model not found at {MODEL_PATH}")

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
            if item.get("blocked", False):
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
        # Initialize canary files for early detection
        init_canaries([str(decoded_path)])
        
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
    init_canaries([path])
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


class BlockRequest(BaseModel):
    file_path: str

@app.post("/block")
def block_file(request: BlockRequest):
    """
    Immediately block (quarantine) a suspicious file.
    """
    file_path = Path(request.file_path)
    
    if not file_path.exists():
        raise HTTPException(404, "File not found")
    
    # First try to kill any process using the file
    success, pids, msg = kill_ransomware_processes(str(file_path))
    
    # Then quarantine
    success, msg = quarantine_file(file_path)
    
    if success:
        # Update results.json to reflect quarantine status
        try:
            results = load_results()
            for f in results.get("files", []):
                if f.get("full_path") == str(file_path):
                    f["quarantined"] = True
                    f["blocked"] = True
                    break
            
            with open(RESULTS_FILE, "w") as f:
                json.dump(results, f, indent=2)
        except Exception as e:
            print(f"[API] Warning: Could not update results.json: {e}")

        return {"status": "blocked", "message": msg, "processes_killed": pids}
    else:
        raise HTTPException(500, msg)


@app.get("/quarantine")
def get_quarantine_list():
    """List all quarantined files."""
    from datetime import datetime
    import json
    
    # Get raw files from quarantine directory
    raw_files = list_quarantined_files()
    
    # Try to load metadata for additional info
    metadata_file = QUARANTINE_DIR / "quarantine_metadata.json"
    metadata = {"quarantined_files": []}
    if metadata_file.exists():
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
        except:
            pass
    
    # Build enriched file list
    files = []
    for raw_file in raw_files:
        # Find matching metadata entry
        original_path = ""
        threat_name = "Unknown Threat"
        for entry in metadata.get("quarantined_files", []):
            if entry.get("quarantine_path", "").endswith(raw_file["name"]):
                original_path = entry.get("original_path", "")
                break
        
        # Determine risk level based on file extension
        filename = raw_file["name"].lower()
        if any(ext in filename for ext in ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr']):
            risk_level = "CRITICAL"
            threat_name = "Ransomware Detected"
        elif any(ext in filename for ext in ['.js', '.jar', '.sh']):
            risk_level = "HIGH"
            threat_name = "Malicious Script"
        else:
            risk_level = "MEDIUM"
            threat_name = "Suspicious File"
        
        files.append({
            "id": raw_file["name"],  # Use filename as ID
            "original_path": original_path,
            "quarantine_path": raw_file["path"],
            "filename": raw_file["name"],
            "size": raw_file["size"],
            "threat_name": threat_name,
            "risk_level": risk_level,
            "quarantine_date": datetime.fromtimestamp(raw_file["quarantine_time"]).isoformat(),
            "status": "quarantined"
        })
    
    return {"files": files}


@app.post("/quarantine/restore")
def restore_quarantined_file(quarantine_name: str = Query(...), destination: str = Query(...)):
    """Restore a quarantined file."""
    import json
    from datetime import datetime
    
    # Check if quarantine file exists
    quarantine_path = QUARANTINE_DIR / quarantine_name
    if not quarantine_path.exists():
        raise HTTPException(404, f"Quarantined file not found: {quarantine_name}")
    
    # Check if destination directory exists, create if not
    dest_path = Path(destination)
    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        raise HTTPException(500, f"Cannot create destination directory: {str(e)}")
    
    success, msg = restore_file(quarantine_name, dest_path)
    
    if success:
        # Update metadata to mark file as restored
        metadata_file = QUARANTINE_DIR / "quarantine_metadata.json"
        try:
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                for entry in metadata.get("quarantined_files", []):
                    if entry.get("quarantine_path", "").endswith(quarantine_name):
                        entry["status"] = "restored"
                        entry["restored_at"] = datetime.now().isoformat()
                        entry["restored_to"] = destination
                        break
                
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=2)
        except Exception as e:
            print(f"[API] Failed to update metadata on restore: {e}")
        
        return {"status": "restored", "message": msg}
    else:
        raise HTTPException(500, msg)


@app.delete("/quarantine/{quarantine_name}")
def delete_quarantined_file_endpoint(quarantine_name: str):
    """Permanently delete a quarantined file."""
    import json
    from datetime import datetime
    
    # Check if quarantine file exists first
    quarantine_path = QUARANTINE_DIR / quarantine_name
    if not quarantine_path.exists():
        raise HTTPException(404, f"Quarantined file not found: {quarantine_name}")
    
    try:
        # Import and call the delete function from quarantine module
        from prevention.quarantine import delete_quarantined_file as delete_file
        success, msg = delete_file(quarantine_name)
    except Exception as e:
        print(f"[API] Error calling delete_quarantined_file: {e}")
        print(f"[API] Traceback: {traceback.format_exc()}")
        raise HTTPException(500, f"Delete operation failed: {str(e)}")
    
    if success:
        # Update metadata to mark file as deleted
        metadata_file = QUARANTINE_DIR / "quarantine_metadata.json"
        try:
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                for entry in metadata.get("quarantined_files", []):
                    if entry.get("quarantine_path", "").endswith(quarantine_name):
                        entry["status"] = "deleted"
                        entry["deleted_at"] = datetime.now().isoformat()
                        break
                
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=2)
        except Exception as e:
            print(f"[API] Failed to update metadata on delete: {e}")
        
        return {"status": "deleted", "message": msg}
    else:
        raise HTTPException(500, msg)


@app.get("/threat-intel")
def get_threat_intel():
    """Get threat intelligence data about scanned files"""
    from collections import Counter
    from utils.results_loader import load_results
    
    results = load_results()
    files = results.get("files", [])
    
    file_types = Counter()
    threat_types = Counter()
    risk_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEARED": 0}
    
    for file in files:
        filename = file.get("filename", "")
        ext = Path(filename).suffix.lower() if filename else "unknown"
        if not ext:
            ext = "no_extension"
        file_types[ext] += 1
        
        risk = file.get("risk_level", "LOW")
        if risk in risk_distribution:
            risk_distribution[risk] += 1
        
        findings = file.get("findings", [])
        if findings:
            threat_types[findings[0].get("description", "Unknown")] += 1
    
    return {
        "file_types": dict(file_types.most_common(20)),
        "threat_types": dict(threat_types.most_common(10)),
        "risk_distribution": risk_distribution,
        "total_files": len(files),
        "threat_count": sum(1 for f in files if f.get("risk_level") in ["CRITICAL", "HIGH", "MEDIUM"])
    }


@app.get("/reports")
def get_reports():
    """Get day-based quarantine reports"""
    from prevention.quarantine import get_quarantine_stats, QUARANTINE_DIR
    import json
    
    stats = get_quarantine_stats()
    
    metadata_file = QUARANTINE_DIR / "quarantine_metadata.json"
    daily_reports = []
    
    if metadata_file.exists():
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            files = metadata.get("quarantined_files", [])
            
            daily_data = {}
            for file_entry in files:
                timestamp = file_entry.get("timestamp", "")
                if timestamp:
                    day = timestamp.split("T")[0]
                    if day not in daily_data:
                        daily_data[day] = {
                            "date": day,
                            "count": 0,
                            "file_types": {},
                            "threats": []
                        }
                    
                    daily_data[day]["count"] += 1
                    
                    file_type = file_entry.get("file_type", "unknown")
                    daily_data[day]["file_types"][file_type] = daily_data[day]["file_types"].get(file_type, 0) + 1
                    
                    threat = file_entry.get("filename", "Unknown")
                    if threat not in daily_data[day]["threats"]:
                        daily_data[day]["threats"].append(threat)
            
            daily_reports = sorted(daily_data.values(), key=lambda x: x["date"], reverse=True)
            
        except Exception as e:
            print(f"[API] Error reading reports: {e}")
    
    return {
        "summary": stats,
        "daily_reports": daily_reports,
        "total_quarantined": stats.get("total_files", 0),
        "total_size_bytes": stats.get("total_size", 0)
    }


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

