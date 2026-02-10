from pathlib import Path
import json
import time
from utils.results_loader import RESULTS_FILE
from .entropy import calculate_entropy

def scan_folder(folder_path: str):
    base = Path(folder_path)

    if not base.exists():
        raise ValueError(f"Path does not exist: {folder_path}")

    files = []

    for p in base.rglob("*"):
        try:
            if p.is_file():
                full_path = str(p)
                entropy = calculate_entropy(full_path)

                # Simple ransomware heuristic: treat typical encrypted extensions
                # as suspicious and mark them as ransomware.
                suspicious_exts = [".rec", ".enc"]
                is_suspicious = any(
                    str(p.name).lower().endswith(ext) for ext in suspicious_exts
                )

                prediction = "ransomware" if is_suspicious else "benign"
                blocked = is_suspicious

                files.append({
                    "filename": str(p.name),
                    "full_path": full_path,
                    "entropy": entropy,
                    "prediction": prediction,
                    "blocked": blocked,
                })
        except PermissionError:
            # Skip files we cannot access
            continue

    results = {
        "timestamp": time.time(),
        "files": files
    }

    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)