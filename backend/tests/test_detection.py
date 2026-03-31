#!/usr/bin/env python3
"""
Extended test suite for the ransomware detection system.
==========================================
Tests three essential properties:
  1. MALICIOUS files ARE detected correctly (true positives)
  2. BENIGN files are NOT flagged or quarantined (no false positives)
  3. Edge-case content (common words like 'delete', 'format') is NOT flagged
"""

import tempfile
import sys
import os
from pathlib import Path

# Add parent directory to path so we can import backend modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from detection.content_analyzer import ContentAnalyzer
from scanner.folder_scanner import process_file
from scanner.entropy import calculate_entropy


PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"

passed = 0
failed = 0


def check(condition: bool, msg: str):
    global passed, failed
    if condition:
        print(f"  {PASS}: {msg}")
        passed += 1
    else:
        print(f"  {FAIL}: {msg}")
        failed += 1


# =============================================================================
# 1. BENIGN FILE TESTS — must NOT be blocked
# =============================================================================

def test_empty_txt_file():
    """An empty .txt file must be CLEARED and not blocked."""
    print("\n>>> test_empty_txt_file")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "empty.txt"
        p.write_text("")

        result = process_file(p, model=None)
        print(f"  risk_score={result['risk_score']}  risk_level={result['risk_level']}  blocked={result['blocked']}")

        check(result["blocked"] is False,        "Empty .txt file must NOT be blocked")
        check(result["risk_score"] == 0,         "Empty .txt file must have risk_score=0")
        check(result["risk_level"] == "CLEARED", "Empty .txt file must be CLEARED")


def test_plain_txt_with_common_words():
    """A .txt file containing words like 'delete', 'format', 'powershell', 'cmd.exe'
    must NOT be treated as malicious — these are everyday English words."""
    print("\n>>> test_plain_txt_with_common_words")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "notes.txt"
        p.write_text(
            "How to format a hard drive.\n"
            "You can delete old files using the delete key.\n"
            "Use cmd.exe or powershell to run commands.\n"
            "System32 is a Windows folder.\n"
        )

        result = process_file(p, model=None)
        print(f"  risk_score={result['risk_score']}  risk_level={result['risk_level']}  blocked={result['blocked']}")

        check(result["blocked"] is False, "Notes .txt with common words must NOT be blocked")
        check(result["risk_score"] < 30,  "Notes .txt with common words must have risk_score < 30")


def test_benign_readme():
    """A typical README.md must be CLEARED."""
    print("\n>>> test_benign_readme")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "README.md"
        p.write_text(
            "# My Project\n\n"
            "A simple project that processes files.\n"
            "You can delete old build files with `rm -rf build/`.\n"
            "Run `format_code.py` to format Python code.\n"
        )

        result = process_file(p, model=None)
        print(f"  risk_score={result['risk_score']}  risk_level={result['risk_level']}  blocked={result['blocked']}")

        check(result["blocked"] is False, "README.md must NOT be blocked")
        check(result["risk_score"] < 30,  "README.md must have risk_score < 30")


def test_json_config_file():
    """A JSON config file must be CLEARED."""
    print("\n>>> test_json_config_file")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "config.json"
        p.write_text('{"debug": true, "log_level": "info", "delete_old_logs": true}')

        result = process_file(p, model=None)
        print(f"  risk_score={result['risk_score']}  risk_level={result['risk_level']}  blocked={result['blocked']}")

        check(result["blocked"] is False, "config.json must NOT be blocked")


# =============================================================================
# 2. SUSPICIOUS TXT — should score but NOT be blocked (needs review only)
# =============================================================================

def test_txt_with_ransom_word():
    """A .txt containing just the word 'ransom' should score LOW but not be blocked."""
    print("\n>>> test_txt_with_ransom_word")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "note.txt"
        p.write_text("ransom")

        result = process_file(p, model=None)
        print(f"  risk_score={result['risk_score']}  risk_level={result['risk_level']}  blocked={result['blocked']}")

        check(result["blocked"] is False, "Single word 'ransom' in .txt must NOT be auto-blocked")
        check(result["risk_score"] < 70,   "Single word 'ransom' must NOT reach blocking threshold")


def test_real_ransom_note():
    """A convincing ransom note must score HIGH and be flagged."""
    print("\n>>> test_real_ransom_note")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "READ_ME.txt"
        p.write_text(
            "YOUR FILES HAVE BEEN ENCRYPTED.\n"
            "To recover your files, send 0.5 Bitcoin to our wallet within 48 hours.\n"
            "Contact us on tor for the unique decryption key.\n"
        )

        result = process_file(p, model=None)
        print(f"  risk_score={result['risk_score']}  risk_level={result['risk_level']}  findings={len(result.get('findings', []))}")

        check(result["risk_score"] >= 60, "Ransom note must score HIGH or above (>=60)")
        check(len(result.get("findings", [])) > 0, "Ransom note must have at least 1 finding")


# =============================================================================
# 3. MALICIOUS SCRIPT TESTS — must be detected and blocked
# =============================================================================

def test_malicious_bat_file():
    """A .bat file deleting System32 must be CRITICAL and blocked."""
    print("\n>>> test_malicious_bat_file")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "evil.bat"
        p.write_text("@echo off\ndel /f /s /q C:\\Windows\\System32\n")

        result = process_file(p, model=None)
        print(f"  risk_score={result['risk_score']}  risk_level={result['risk_level']}  blocked={result['blocked']}")

        check(result["risk_score"] >= 80, "System32-deleting .bat must score CRITICAL (>=80)")
        check(result["blocked"] is True,   "System32-deleting .bat must be blocked")


def test_malicious_powershell():
    """A .ps1 file disabling Defender must be CRITICAL."""
    print("\n>>> test_malicious_powershell")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "evil.ps1"
        p.write_text("Set-MpPreference -DisableRealtimeMonitoring $true\n"
                     "Get-ChildItem -Recurse | Remove-Item -Force\n")

        result = process_file(p, model=None)
        print(f"  risk_score={result['risk_score']}  risk_level={result['risk_level']}  blocked={result['blocked']}")

        check(result["risk_score"] >= 60, "Defender-disabling .ps1 must score HIGH or above (>=60)")
        check(result["blocked"] is True,   ".ps1 with malicious patterns must be blocked")


def test_benign_bat_file():
    """A benign .bat with only echo and dir commands must NOT be blocked."""
    print("\n>>> test_benign_bat_file")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "build.bat"
        p.write_text("@echo off\necho Building project...\ndir /s\npause\n")

        result = process_file(p, model=None)
        print(f"  risk_score={result['risk_score']}  risk_level={result['risk_level']}  blocked={result['blocked']}")

        check(result["blocked"] is False, "Benign build.bat must NOT be blocked")
        check(result["risk_score"] < 60,   "Benign build.bat must score below HIGH threshold")


# =============================================================================
# 4. CONTENT ANALYZER UNIT TESTS
# =============================================================================

def test_content_analyzer_empty():
    print("\n>>> content_analyzer: empty text")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "a.txt"
        p.write_text("")
        result = ContentAnalyzer.analyze_file(str(p))
        print(f"  risk_score={result['risk_score']}  findings={len(result.get('findings', []))}")
        check(result["risk_score"] == 0, "Empty file must score 0 in content analyzer")


def test_content_analyzer_common_words():
    print("\n>>> content_analyzer: innocent common words")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "doc.txt"
        p.write_text("delete format powershell cmd.exe system32 encrypt wallet bitcoin")
        result = ContentAnalyzer.analyze_file(str(p))
        print(f"  risk_score={result['risk_score']}  findings={len(result.get('findings', []))}")
        # 'encrypt' + 'bitcoin' together in text is a medium signal but still should
        # NOT exceed the blocking threshold (70) by itself
        check(result["risk_score"] < 70, "Common words alone must not reach blocking threshold")


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("\n" + "=" * 70)
    print("RECONWARE DETECTION — EXTENDED TEST SUITE")
    print("=" * 70)

    # Benign file tests
    test_empty_txt_file()
    test_plain_txt_with_common_words()
    test_benign_readme()
    test_json_config_file()

    # Suspicious-but-not-blocked tests
    test_txt_with_ransom_word()
    test_real_ransom_note()

    # Malicious file tests
    test_malicious_bat_file()
    test_malicious_powershell()
    test_benign_bat_file()

    # Content analyzer unit tests
    test_content_analyzer_empty()
    test_content_analyzer_common_words()

    print("\n" + "=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed out of {passed + failed} checks")
    print("=" * 70)
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
