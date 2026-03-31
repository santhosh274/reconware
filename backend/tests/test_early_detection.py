import os
import sys
import time
import json
from pathlib import Path

# Add parent directory to path so we can import backend modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from detection.canary_manager import CanaryManager
from detection.content_analyzer import ContentAnalyzer

def test_canary_logic():
    print("--- Testing Canary Logic ---")
    test_dir = Path("./test_canaries")
    test_dir.mkdir(exist_ok=True)
    
    manager = CanaryManager([str(test_dir)])
    manager.deploy_canaries()
    time.sleep(1.1)
    
    canaries = list(manager.canaries.keys())
    print(f"Deployed {len(canaries)} canaries.")
    
    # Test 1: Check tampered (no change)
    c_path = canaries[0]
    is_tampered = manager.check_canary_tampered(c_path)
    stored_mtime = manager.canaries[c_path]["mtime"]
    actual_mtime = int(Path(c_path).stat().st_mtime)
    print(f"Canary 0: {c_path}")
    print(f"  Stored mtime: {stored_mtime}, Actual mtime: {actual_mtime}")
    print(f"Canary 0 tampered (initial): {is_tampered}")
    
    # Test 2: Modify canary
    time.sleep(1.1) # Ensure mtime changes
    with open(canaries[0], "a") as f:
        f.write("\nTAMPERED!")
    
    is_tampered = manager.check_canary_tampered(canaries[0])
    print(f"Canary 0 tampered (after write): {is_tampered}")
    
    # Cleanup
    for c in canaries:
        if os.name == 'nt':
            os.system(f'attrib -h "{c}"')
        os.remove(c)
    test_dir.rmdir()
    print("Canary logic test complete.")

def test_system_tool_detection():
    print("\n--- Testing System Tool Detection ---")
    malicious_scripts = [
        ("clean_shadows.bat", "vssadmin delete shadows /all /quiet"),
        ("stop_backups.ps1", "wbadmin delete catalog -quiet"),
        ("disable_recovery.cmd", "bcdedit /set {default} recoveryenabled no")
    ]
    
    for filename, content in malicious_scripts:
        with open(filename, "w") as f:
            f.write(content)
        
        result = ContentAnalyzer.analyze_file(filename)
        print(f"File: {filename}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Risk Level: {result['risk_level']}")
        for fnd in result['findings']:
            print(f"  Finding: {fnd['description']}")
        
        os.remove(filename)

if __name__ == "__main__":
    test_canary_logic()
    test_system_tool_detection()
