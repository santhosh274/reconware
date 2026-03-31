import os
from pathlib import Path
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
from .entropy import calculate_entropy
from detection.content_analyzer import ContentAnalyzer
from .file_analyzer import analyze_file


def _is_pe_file(file_path: Path) -> bool:
    """
    Check if a file is a Windows PE binary by reading the MZ magic bytes.
    The RandomForest model was trained on PE-header features, so we should
    only run it against actual PE files. Running it on other file types with
    all-zero feature vectors almost always produces a false 'ransomware' result.
    """
    try:
        with open(file_path, "rb") as f:
            magic = f.read(2)
        return magic == b"MZ"
    except Exception:
        return False


def process_file(file_path: Path, model=None):
    """
    Enhanced file processing with content analysis.
    Combines entropy, ML prediction (PE files only), and content analysis
    for robust, accurate risk scoring.

    Risk Levels:
      CLEARED  - risk score  0-19  → no action
      LOW      - risk score 20-39  → flagged, no block
      MEDIUM   - risk score 40-59  → flagged, no block
      HIGH     - risk score 60-79  → flagged, no block (manual review)
      CRITICAL - risk score 80-100 → quarantined immediately
    """
    # Calculate entropy
    entropy = calculate_entropy(str(file_path))

    # Run content analysis for text/script files
    content_analysis = ContentAnalyzer.analyze_file(str(file_path))

    # Get risk score from content analysis
    content_risk_score = content_analysis.get("risk_score", 0) or 0
    file_type = content_analysis.get("file_type", "unknown")
    analysis_type = content_analysis.get("analysis_type", "unknown")
    findings = content_analysis.get("findings", [])

    # --- ML prediction: ONLY run for PE (executable) files ---
    is_pe = _is_pe_file(file_path)
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
    # Normal plaintext:   3.0 – 5.5 bits/byte → no risk added
    # Compressed/media:   5.5 – 7.0 bits/byte → low contribution
    # Encrypted/suspect:  7.0 – 7.5 bits/byte → medium contribution
    # High-confidence enc: ≥7.5 bits/byte      → high contribution
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

    elif file_type in ["batch", "powershell", "vbscript", "bash","python"]:
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
        # (avoids flagging compressed but legitimate files like images/zips)
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

    # --- Build result ---
    return {
        # Core fields
        "filename": file_path.name,
        "full_path": str(file_path),
        "entropy": round(entropy, 4),
        "prediction": ml_prediction,           # 0 = ransomware, 1 = benign (old format compat)
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


def scan_folder(folder_path: str, model=None):
    """
    Recursively scan folder and detect ransomware-like files.
    Optimized with parallel processing.
    """
    base = Path(folder_path)
    if not base.exists():
        raise ValueError(f"Path does not exist: {folder_path}")

    # Gather all candidate files first
    all_files = [p for p in base.rglob("*") if p.is_file()]
    results = []

    # Use a thread pool for parallel processing (feature extraction is IO/CPU mixed)
    # Using max_workers derived from CPU count or a fixed number for better response
    max_workers = min(32, (os.cpu_count() or 4) * 4)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_file = {executor.submit(process_file, p, model): p for p in all_files}
        
        # Process as they complete
        for future in as_completed(future_to_file):
            p = future_to_file[future]
            try:
                file_info = future.result()
                if file_info:
                    results.append(file_info)
            except PermissionError:
                continue
            except Exception as e:
                print(f"Error processing {p}: {e}")
                continue

    return results
