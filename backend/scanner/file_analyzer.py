import os
import shutil
import joblib
import numpy as np
from pathlib import Path
from .entropy import file_entropy, calculate_entropy
from .api_detector import scan_keywords

# Use absolute path for quarantine directory within backend folder
BASE_DIR = Path(__file__).resolve().parent
QUARANTINE_DIR = BASE_DIR.parent / "quarantine"

# Model path - use the trained model in scanner folder
MODEL_PATH = BASE_DIR / "ransomware_model.pkl"


def _is_pe_file(file_path: Path) -> bool:
    """
    Check if a file is a Windows PE binary by reading the MZ magic bytes.
    """
    try:
        with open(file_path, "rb") as f:
            magic = f.read(2)
        return magic == b"MZ"
    except Exception:
        return False


def analyze_file(file_path, model=None):
    """
    Analyze a file for ransomware indicators.
    Returns a dictionary with all required fields matching the frontend schema.
    """
    file_path_str = str(file_path)
    file_path_obj = Path(file_path_str)

    # Load model if not provided
    if model is None:
        if not MODEL_PATH.exists():
            # Fallback to alternate model location
            alt_model_path = Path("model/random_forest.pkl")
            if alt_model_path.exists():
                model = joblib.load(alt_model_path)
            else:
                raise FileNotFoundError(f"Model not found at {MODEL_PATH}")
        else:
            model = joblib.load(MODEL_PATH)

    # Calculate entropy
    entropy = calculate_entropy(file_path_str)

    # Run content analysis for text/script files
    from detection.content_analyzer import ContentAnalyzer
    content_analysis = ContentAnalyzer.analyze_file(file_path_str)

    # Get risk score from content analysis
    content_risk_score = content_analysis.get("risk_score", 0) or 0
    file_type = content_analysis.get("file_type", "unknown")
    analysis_type = content_analysis.get("analysis_type", "unknown")
    findings = content_analysis.get("findings", [])

    # --- ML prediction: ONLY run for PE (executable) files ---
    is_pe = _is_pe_file(file_path_obj)
    ml_prediction = 1   # default = benign
    ml_confidence = 0.0
    ml_used = False

    if is_pe and model is not None:
        try:
            features = np.zeros((1, model.n_features_in_))
            features[0][0] = entropy
            ml_prediction = int(model.predict(features)[0])
            try:
                proba = model.predict_proba(features)[0]
                ml_confidence = float(max(proba))
            except Exception:
                ml_confidence = 0.8
            ml_used = True
        except Exception:
            ml_prediction = 1  # fallback to benign on error

    # --- Entropy scoring (calibrated to real-world byte distributions) ---
    if entropy >= 7.5:
        entropy_score = 60   # HIGH – very likely encrypted
    elif entropy >= 7.2:
        entropy_score = 40   # MEDIUM
    elif entropy >= 6.8:
        entropy_score = 20   # LOW – could be compressed/binary
    else:
        entropy_score = 0    # Normal range – no risk

    # --- Build combined risk score ---
    combined_risk_score = 0

    if file_type == "encrypted":
        # File has a known ransomware extension → immediately critical
        combined_risk_score = 100

    elif file_type in ["batch", "powershell", "vbscript", "bash", "python"]:
        # Script files: content analysis is the primary signal
        combined_risk_score = content_risk_score
        # Entropy can boost the score for packed/obfuscated scripts
        combined_risk_score = max(combined_risk_score, entropy_score)

    elif is_pe and ml_used:
        # PE executables: combine entropy + ML
        # ml_prediction 0 = ransomware (model output)
        ml_risk = 80 if ml_prediction == 0 else 20
        # Weighted: 60% ML, 40% entropy
        combined_risk_score = int(round(ml_risk * 0.6 + entropy_score * 0.4))

    else:
        # Generic text/binary files: content analysis + entropy only
        combined_risk_score = content_risk_score
        # Only boost from entropy if content score is already elevated
        if content_risk_score >= 30:
            combined_risk_score = max(combined_risk_score, entropy_score)

    combined_risk_score = min(100, combined_risk_score)

    # --- Determine risk level ---
    if combined_risk_score >= 80:
        risk_level = "CRITICAL"
    elif combined_risk_score >= 60:
        risk_level = "HIGH"
    elif combined_risk_score >= 40:
        risk_level = "MEDIUM"
    elif combined_risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "CLEARED"

    # --- Blocking decision ---
    # Only block files that are confirmed dangerous (threshold = 70)
    blocked = False

    if file_type == "encrypted":
        # Known ransomware extension → always block
        blocked = True
    elif file_type in ["batch", "powershell", "vbscript", "bash", "python"] and findings:
        # Script with actual malicious patterns found → block if HIGH or above
        blocked = combined_risk_score >= 60
    elif combined_risk_score >= 70:
        # Any file type at HIGH/CRITICAL risk score → block
        blocked = True

    # --- Build result with correct schema for frontend ---
    return {
        # Core fields (matching frontend ScannedFileSchema)
        "filename": file_path_obj.name,
        "full_path": file_path_str,
        "entropy": round(entropy, 4),
        "prediction": ml_prediction,           # 0 = ransomware, 1 = benign
        "blocked": blocked,

        # Extended fields
        "ml_prediction": "Ransomware" if ml_prediction == 0 else "Benign",
        "ml_confidence": round(ml_confidence, 4),
        "ml_used": ml_used,
        "is_pe_file": is_pe,
        "risk_score": combined_risk_score,
        "risk_level": risk_level,
        "file_type": file_type,
        "analysis_type": analysis_type,
        "content_risk_score": content_risk_score,
        "findings": findings,
    }


def quarantine(file_path):
    """Move a file to quarantine directory."""
    # Ensure quarantine directory exists
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    filename = os.path.basename(file_path)
    dest = QUARANTINE_DIR / filename

    # Handle filename conflicts
    counter = 1
    while dest.exists():
        name, ext = os.path.splitext(filename)
        dest = QUARANTINE_DIR / f"{name}_{counter}{ext}"
        counter += 1

    try:
        shutil.move(file_path, str(dest))
        print(f"[QUARANTINE] {filename} moved to {QUARANTINE_DIR}")
    except Exception as e:
        print(f"Quarantine failed: {e}")

