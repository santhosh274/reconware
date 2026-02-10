import os
from ..scanner.entropy import calculate_entropy

def scan_folder(folder):
    results = []
    for root, _, files in os.walk(folder):
        for file in files:
            path = os.path.join(root, file)
            entropy = calculate_entropy(path)
            results.append({
                "file": file,
                "path": path,
                "entropy": entropy
            })
    return results
