from pathlib import Path
import json

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_FILE = BASE_DIR / "storage" / "results.json"


def load_results():
    if not RESULTS_FILE.exists():
        return {"timestamp": None, "files": []}

    try:
        with RESULTS_FILE.open("r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {"timestamp": None, "files": []}
            return json.loads(content)
    except json.JSONDecodeError:
        return {"timestamp": None, "files": []}
