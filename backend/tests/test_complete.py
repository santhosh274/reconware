#!/usr/bin/env python3
"""
Comprehensive Test Suite for ReconWare Ransomware Detection System
=====================================================================
Tests all core functionalities:
1. Content Analysis - Detection of malicious patterns
2. Entropy Calculation - Encrypted file detection  
3. Canary Manager - Early stage detection
4. Quarantine Operations - File isolation and management
5. Process Killer - Malware process termination
6. Folder Scanner - Complete scan workflow
7. ML Integration - Random Forest model predictions
"""

import sys
import os
import tempfile
import shutil
import json
import time
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
os.chdir(str(Path(__file__).parent.parent))

from detection.content_analyzer import ContentAnalyzer
from scanner.entropy import calculate_entropy
from detection.canary_manager import CanaryManager
from prevention.quarantine import quarantine_file, restore_file, list_quarantined_files, QUARANTINE_DIR
from prevention.process_killer import kill_process_by_name, get_process_using_file, kill_parent_and_children
from scanner.folder_scanner import process_file, scan_folder


PASS = "PASS"
FAIL = "FAIL"


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def add(self, passed, test_name, message=""):
        status = PASS if passed else FAIL
        self.tests.append(f"  {status}: {test_name}")
        if message:
            self.tests.append(f"       {message}")
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def summary(self):
        total = self.passed + self.failed
        return f"\n{'='*70}\nRESULTS: {self.passed} passed, {self.failed} failed out of {total} tests\n{'='*70}"


results = TestResults()


def check(condition, test_name, message=""):
    results.add(condition, test_name, message)
    return condition


# =============================================================================
# TEST 1: ENTROPY CALCULATION
# =============================================================================
print("\n>>> TEST 1: Entropy Calculation")

def test_entropy_calculation():
    with tempfile.TemporaryDirectory() as tmp:
        # Low entropy: repeated characters
        low_entropy_file = Path(tmp) / "low_entropy.txt"
        low_entropy_file.write_text("aaaaaaaaaaabbbbbbbbbbcccccccccc")
        low_entropy = calculate_entropy(str(low_entropy_file))
        
        check(low_entropy < 4.0, "Low entropy for repetitive text", f"entropy={low_entropy:.2f}")
        
        # Medium entropy: normal text
        medium_entropy_file = Path(tmp) / "normal.txt"
        medium_entropy_file.write_text("This is a normal text file with some random content 12345")
        medium_entropy = calculate_entropy(str(medium_entropy_file))
        
        check(3.0 < medium_entropy < 6.0, "Medium entropy for normal text", f"entropy={medium_entropy:.2f}")
        
        # High entropy: random data (simulated encryption)
        high_entropy_file = Path(tmp) / "high_entropy.bin"
        high_entropy_file.write_bytes(os.urandom(10000))
        high_entropy = calculate_entropy(str(high_entropy_file))
        
        check(high_entropy > 7.0, "High entropy for random data", f"entropy={high_entropy:.2f}")

test_entropy_calculation()


# =============================================================================
# TEST 2: CONTENT ANALYZER - MALICIOUS PATTERNS
# =============================================================================
print("\n>>> TEST 2: Content Analyzer - Malicious Pattern Detection")

def test_malicious_patterns():
    with tempfile.TemporaryDirectory() as tmp:
        # Test batch file with system32 deletion
        bat_file = Path(tmp) / "malicious.bat"
        bat_file.write_text("@echo off\ndel /f /s /q C:\\Windows\\System32\n")
        result = ContentAnalyzer.analyze_file(str(bat_file))
        
        check(result["risk_score"] >= 90, "Batch file with System32 deletion", f"score={result['risk_score']}")
        
        # Test PowerShell with Defender disable
        ps1_file = Path(tmp) / "disable_defender.ps1"
        ps1_file.write_text("Set-MpPreference -DisableRealtimeMonitoring $true\n")
        result = ContentAnalyzer.analyze_file(str(ps1_file))
        
        check(result["risk_score"] >= 70, "PowerShell disabling Defender", f"score={result['risk_score']}")
        
        # Test vssadmin (ransomware early stage)
        vss_file = Path(tmp) / "delete_shadows.bat"
        vss_file.write_text("vssadmin delete shadows /all /quiet\n")
        result = ContentAnalyzer.analyze_file(str(vss_file))
        
        check(result["risk_score"] >= 90, "vssadmin shadow copy deletion", f"score={result['risk_score']}")

test_malicious_patterns()


# =============================================================================
# TEST 3: CONTENT ANALYZER - BENIGN FILES
# =============================================================================
print("\n>>> TEST 3: Content Analyzer - Benign Files")

def test_benign_files():
    with tempfile.TemporaryDirectory() as tmp:
        # Empty file
        empty_file = Path(tmp) / "empty.txt"
        empty_file.write_text("")
        result = ContentAnalyzer.analyze_file(str(empty_file))
        
        check(result["risk_score"] == 0, "Empty file score is 0", f"score={result['risk_score']}")
        
        # Normal code
        code_file = Path(tmp) / "main.py"
        code_file.write_text("def hello():\n    print('Hello World')\n")
        result = ContentAnalyzer.analyze_file(str(code_file))
        
        check(result["risk_score"] < 30, "Normal Python code is safe", f"score={result['risk_score']}")
        
        # README with common words
        readme_file = Path(tmp) / "README.md"
        readme_file.write_text("# My Project\nDelete old files with rm command\n")
        result = ContentAnalyzer.analyze_file(str(readme_file))
        
        check(result["risk_score"] < 30, "README with common words", f"score={result['risk_score']}")

test_benign_files()


# =============================================================================
# TEST 4: RANSOMWARE EXTENSION DETECTION
# =============================================================================
print("\n>>> TEST 4: Ransomware Extension Detection")

def test_ransomware_extensions():
    with tempfile.TemporaryDirectory() as tmp:
        for ext in ['.encrypted', '.locked', '.crypto', '.ransom', '.enc']:
            encrypted_file = Path(tmp) / f"file{ext}"
            encrypted_file.write_bytes(b"encrypted content")
            
            result = ContentAnalyzer.analyze_file(str(encrypted_file))
            
            check(result["risk_score"] == 100, f"Ransomware extension {ext} detected", 
                  f"score={result['risk_score']}, level={result['risk_level']}")

test_ransomware_extensions()


# =============================================================================
# TEST 5: CANARY MANAGER
# =============================================================================
print("\n>>> TEST 5: Canary Manager - Early Stage Detection")

def test_canary_manager():
    with tempfile.TemporaryDirectory() as tmp:
        manager = CanaryManager([tmp])
        manager.deploy_canaries()
        
        canaries = list(manager.canaries.keys())
        check(len(canaries) >= 2, "Canaries deployed", f"count={len(canaries)}")
        
        # Test tampered detection
        if canaries:
            time.sleep(1.1)  # Ensure mtime changes
            with open(canaries[0], "a") as f:
                f.write("modified")
            
            tampered = manager.check_canary_tampered(canaries[0])
            check(tampered, "Canary tamper detection", f"tampered={tampered}")

test_canary_manager()


# =============================================================================
# TEST 6: FOLDER SCANNER - PROCESS FILE
# =============================================================================
print("\n>>> TEST 6: Folder Scanner - Process File")

def test_process_file():
    with tempfile.TemporaryDirectory() as tmp:
        # Malicious file
        malicious = Path(tmp) / "evil.bat"
        malicious.write_text("vssadmin delete shadows /all /quiet\nformat C: /q\n")
        
        result = process_file(malicious, model=None)
        
        check(result["risk_score"] >= 80, "Process file detects malicious", 
              f"score={result['risk_score']}, level={result['risk_level']}")
        check(result["blocked"] == True, "Malicious file blocked", f"blocked={result['blocked']}")
        
        # Benign file
        benign = Path(tmp) / "readme.txt"
        benign.write_text("This is a README file with normal content.")
        
        result = process_file(benign, model=None)
        
        check(result["risk_score"] < 30, "Benign file low risk", f"score={result['risk_score']}")
        check(result["blocked"] == False, "Benign file not blocked", f"blocked={result['blocked']}")

test_process_file()


# =============================================================================
# TEST 7: FOLDER SCANNER - SCAN FOLDER
# =============================================================================
print("\n>>> TEST 7: Folder Scanner - Complete Scan")

def test_scan_folder():
    with tempfile.TemporaryDirectory() as tmp:
        # Create test files
        (Path(tmp) / "clean1.txt").write_text("hello world")
        (Path(tmp) / "clean2.py").write_text("print('hi')")
        
        subdir = Path(tmp) / "subdir"
        subdir.mkdir()
        (subdir / "malicious.bat").write_text("del /f /s /q C:\\Windows\\System32")
        
        results = scan_folder(tmp, model=None)
        
        check(len(results) >= 3, "Scan finds all files", f"count={len(results)}")
        
        blocked = [r for r in results if r.get("blocked")]
        check(len(blocked) > 0, "Malicious file detected and blocked", f"blocked={len(blocked)}")

test_scan_folder()


# =============================================================================
# TEST 8: QUARANTINE OPERATIONS
# =============================================================================
print("\n>>> TEST 8: Quarantine Operations")

def test_quarantine_operations():
    with tempfile.TemporaryDirectory() as tmp:
        # Create and quarantine a file
        test_file = Path(tmp) / "test_malware.exe"
        test_file.write_text("malicious content")
        
        success, message = quarantine_file(test_file)
        
        check(success, "File quarantined successfully", message)
        
        # Check quarantine directory
        quarantined = list_quarantined_files()
        
        check(len(quarantined) > 0, "File in quarantine list", f"count={len(quarantined)}")
        
        # Test restore
        if quarantined:
            restore_path = Path(tmp) / "restored.exe"
            success, msg = restore_file(quarantined[0]["name"], restore_path)
            
            check(success, "File restored successfully", msg)
            check(restore_path.exists(), "Restored file exists")

test_quarantine_operations()


# =============================================================================
# TEST 9: PROCESS KILLER
# =============================================================================
print("\n>>> TEST 9: Process Killer")

def test_process_killer():
    # Test get_process_using_file with a non-existent file
    processes = get_process_using_file("C:\\non_existent_file_12345.exe")
    
    check(isinstance(processes, list), "Process listing returns list", f"type={type(processes)}")
    check(len(processes) == 0, "No processes for non-existent file", f"count={len(processes)}")
    
    # Test kill_parent_and_children with invalid PID
    success, pids = kill_parent_and_children(999999, force=True)
    
    check(success == False, "Invalid PID returns False", f"success={success}")

test_process_killer()


# =============================================================================
# TEST 10: COMBINED RISK SCORING
# =============================================================================
print("\n>>> TEST 10: Combined Risk Scoring")

def test_combined_risk():
    with tempfile.TemporaryDirectory() as tmp:
        # Test various combinations
        test_cases = [
            ("ransom_note.txt", "Your files have been encrypted. Send 0.5 bitcoin to recover.", 60),
            ("clean.txt", "just a normal text file", 0),
            ("script.bat", "@echo off\necho hello", 0),
        ]
        
        for filename, content, min_score in test_cases:
            file_path = Path(tmp) / filename
            file_path.write_text(content)
            
            result = process_file(file_path, model=None)
            
            check(result["risk_score"] >= min_score, f"Risk score for {filename}", 
                  f"score={result['risk_score']}, expected>={min_score}")

test_combined_risk()


# =============================================================================
# TEST 11: EDGE CASES
# =============================================================================
print("\n>>> TEST 11: Edge Cases")

def test_edge_cases():
    with tempfile.TemporaryDirectory() as tmp:
        # Binary file (non-text)
        binary = Path(tmp) / "binary.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 100)  # PE header
        
        result = process_file(binary, model=None)
        
        check(result["file_type"] == "binary", "Binary file detected", f"type={result['file_type']}")
        
        # Very long filename
        long_name = Path(tmp) / f"{'a' * 200}.txt"
        long_name.write_text("test")
        
        result = process_file(long_name, model=None)
        
        check(result is not None, "Long filename handled", f"filename={result['filename'][:50]}...")

test_edge_cases()


# =============================================================================
# PRINT SUMMARY
# =============================================================================
print("\n".join(results.tests))
print(results.summary())

if results.failed > 0:
    sys.exit(1)
else:
    print("\nAll tests passed! System is working correctly.")