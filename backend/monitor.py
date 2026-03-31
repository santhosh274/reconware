import time
import json
import threading
import os
import psutil
from typing import List
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from scanner.folder_scanner import process_file
from prevention.quarantine import quarantine_file, QUARANTINE_DIR
from prevention.process_killer import kill_ransomware_processes, get_process_using_file, kill_parent_and_children
from detection.canary_manager import CanaryManager

# Global model reference (set from main.py)
_model = None
_canary_manager = None

# Configuration for early detection thresholds
HIGH_RISK_THRESHOLD = 60  # Block and kill process immediately
MEDIUM_RISK_THRESHOLD = 40  # Quarantine file

# Track recent file changes to detect rapid encryption (ransomware behavior)
FILE_CHANGE_TRACKER = {}
RAPID_CHANGE_THRESHOLD = 5  # Number of file changes to trigger rapid encryption detection
RAPID_CHANGE_TIME_WINDOW = 10  # Seconds


def set_model(model):
    global _model
    _model = model


def init_canaries(folders_to_watch: List[str]):
    global _canary_manager
    _canary_manager = CanaryManager(folders_to_watch)
    _canary_manager.deploy_canaries()


class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, folder_to_watch, results_file):
        self.folder = Path(folder_to_watch)
        self.results_file = Path(results_file)
        self.lock = threading.Lock()
        self._change_tracker = {}  # Track file changes per directory

    def _process_file(self, file_path: Path):
        """Scan one file, quarantine if needed, and update results.json."""
        # 1. Check for canary tampering (HIGHLY SENSITIVE)
        if _canary_manager and _canary_manager.is_canary_file(str(file_path)):
            if _canary_manager.check_canary_tampered(str(file_path)):
                print(f"[Monitor] [ALERT] CANARY TAMPERED: {file_path}")
                self._handle_critical_threat(file_path, "CANARY_TRIGGERED")
            return

        # Ignore files inside quarantine directory
        if str(file_path).startswith(str(QUARANTINE_DIR)):
            return

        if not file_path.is_file():
            return

        # Skip files that are likely to be temporary or system files
        if file_path.suffix.lower() in ['.tmp', '.temp', '.swp', '.lock']:
            return

        print(f"[Monitor] Processing file: {file_path}")

        # Use enhanced file processing with ML + content analysis
        file_info = process_file(file_path, _model)

        # Early detection: Check for ransomware-like behavior
        risk_score = file_info.get("risk_score", 0)
        risk_level = file_info.get("risk_level", "CLEARED")
        findings = file_info.get("findings", [])
        
        # Check for system tool malicious usage in findings
        is_system_tool_attack = any("vssadmin" in f.get('description', '').lower() or 
                                    "shadows" in f.get('description', '').lower() or
                                    "wbadmin" in f.get('description', '').lower()
                                    for f in findings)
        
        # Check for rapid file changes (encryption behavior)
        directory = str(file_path.parent)
        current_time = time.time()
        
        if directory not in self._change_tracker:
            self._change_tracker[directory] = []
        
        # Add current change
        self._change_tracker[directory].append(current_time)
        
        # Remove old entries outside time window
        self._change_tracker[directory] = [
            t for t in self._change_tracker[directory]
            if current_time - t < RAPID_CHANGE_TIME_WINDOW
        ]
        
        # Detect rapid encryption behavior
        rapid_changes = len(self._change_tracker[directory])
        is_rapid_encryption = rapid_changes >= RAPID_CHANGE_THRESHOLD
        
        if is_rapid_encryption:
            print(f"[Monitor] [WARN] RAPID ENCRYPTION DETECTED in {directory}!")
            print(f"[Monitor] {rapid_changes} file changes in {RAPID_CHANGE_TIME_WINDOW} seconds")
            
            # Kill processes in this directory
            self._kill_processes_in_directory(directory)
        
        # Determine action based on risk level
        should_block = file_info.get("blocked", False)
        should_kill_process = False
        action_taken = "none"
        
        # High risk or critical - kill process and quarantine
        if is_system_tool_attack:
            should_kill_process = True
            should_block = True
            action_taken = "BLOCKED_SYSTEM_TOOL_ATTACK"
        elif risk_score >= HIGH_RISK_THRESHOLD or risk_level == "CRITICAL":
            should_kill_process = True
            should_block = True
            action_taken = "BLOCKED_HIGH_RISK"
        elif is_rapid_encryption:
            should_kill_process = True
            should_block = True
            action_taken = "BLOCKED_RAPID_ENCRYPTION"
        elif risk_score >= MEDIUM_RISK_THRESHOLD:
            should_block = True
            action_taken = "BLOCKED_MEDIUM_RISK"
        
        # Kill the process if needed (early detection at execution state)
        if should_kill_process:
            print(f"[Monitor] [ALERT] KILLING PROCESS for: {file_path}")
            success, killed_pids, message = kill_ransomware_processes(str(file_path))
            if success:
                print(f"[Monitor] [OK] Killed {len(killed_pids)} process(es): {killed_pids}")
                file_info["process_killed"] = True
                file_info["killed_pids"] = killed_pids
            else:
                print(f"[Monitor] [WARN] Could not kill process: {message}")
                file_info["process_killed"] = False
                file_info["kill_error"] = message
        
        # Quarantine if flagged
        if should_block:
            print(f"[Monitor] [ACTION] Quarantining: {file_path}")
            success, message = quarantine_file(file_path)
            if success:
                print(f"[Monitor] [OK] Quarantined: {message}")
                file_info["quarantined"] = True
            else:
                print(f"[Monitor] [WARN] Quarantine failed: {message}")
                file_info["quarantined"] = False
                file_info["quarantine_error"] = message
        
        file_info["action_taken"] = action_taken
        file_info["rapid_encryption_detected"] = is_rapid_encryption
        
        # Update results.json
        self._update_results_file(file_info)

    def _handle_critical_threat(self, file_path: Path, threat_type: str):
        """Immediate response to high-confidence threats (e.g. Canary)"""
        file_info = {
            "filename": file_path.name,
            "full_path": str(file_path),
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "action_taken": threat_type,
            "blocked": True,
            "findings": [{"description": f"Critical Early Stage Detection: {threat_type}", "severity": 100}]
        }
        
        # Kill everything in the directory
        self._kill_processes_in_directory(str(file_path.parent))
        
        # Quarantine if possible
        quarantine_file(file_path)
        
        file_info["quarantined"] = True
        file_info["process_killed"] = True
        
        self._update_results_file(file_info)


    def _kill_processes_in_directory(self, directory: str):
        """
        Kill all processes that have files open in the given directory.
        This is critical for stopping ransomware that is actively encrypting files.
        """
        print(f"[Monitor] Searching for processes using files in: {directory}")
        
        killed_any = False
        
        for proc in psutil.process_iter(['pid', 'exe', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                cmdline = proc_info.get('cmdline', [])
                
                if not cmdline:
                    continue
                
                # Check if any command line argument references this directory
                for arg in cmdline:
                    if arg and directory.lower() in arg.lower():
                        pid = proc_info['pid']
                        print(f"[Monitor] Killing process {pid} ({proc_info.get('name', 'unknown')})")
                        success, pids = kill_parent_and_children(pid, force=True)
                        if success:
                            killed_any = True
                        break
                        
            except Exception as e:
                continue
        
        if killed_any:
            print(f"[Monitor] [OK] Terminated processes in ransomware activity directory")
        else:
            print(f"[Monitor] [WARN] No processes found to kill in directory")

    def _update_results_file(self, new_entry):
        with self.lock:
            # Read existing data
            try:
                with open(self.results_file, "r") as f:
                    data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                data = {"timestamp": None, "files": []}

            # Remove old entry for same file (if any)
            files = data["files"]
            files = [f for f in files if f["full_path"] != new_entry["full_path"]]
            files.append(new_entry)
            data["files"] = files
            data["timestamp"] = time.time()

            # Write to temp then replace (atomic)
            temp = self.results_file.with_suffix(".tmp")
            with open(temp, "w") as f:
                json.dump(data, f, indent=2)
            temp.replace(self.results_file)

    def on_created(self, event):
        """Handle new file creation events - could be ransomware creating encrypted files"""
        if not event.is_directory:
            file_path = Path(event.src_path)
            
            # Check if new file has ransomware extension
            ransomware_exts = ['.encrypted', '.locked', '.enc', '.ransom', '.crypto', '.key']
            if file_path.suffix.lower() in ransomware_exts:
                print(f"[Monitor] [ALERT] NEW RANSOMWARE FILE DETECTED: {file_path}")
                # Immediately process this file
                self._process_file(file_path)
            else:
                self._process_file(file_path)

    def on_modified(self, event):
        """Handle file modification events - could be ransomware encrypting existing files"""
        if not event.is_directory:
            self._process_file(Path(event.src_path))

    def on_deleted(self, event):
        """Handle file deletion events - track for potential ransomware"""
        if not event.is_directory:
            self._remove_from_results(Path(event.src_path))
            print(f"[Monitor] [WARN] File deleted: {event.src_path}")

    def on_moved(self, event):
        """Handle file move/rename events - could be ransomware changing file extensions"""
        if not event.is_directory:
            # Process the new file location
            self._process_file(Path(event.dest_path))
            # Remove old location from results
            self._remove_from_results(Path(event.src_path))
            
            print(f"[Monitor] [WARN] File renamed/moved: {event.src_path} -> {event.dest_path}")

    def _remove_from_results(self, file_path):
        with self.lock:
            try:
                with open(self.results_file, "r") as f:
                    data = json.load(f)
            except:
                return
            files = [f for f in data["files"] if f["full_path"] != str(file_path)]
            if len(files) != len(data["files"]):
                data["files"] = files
                data["timestamp"] = time.time()
                temp = self.results_file.with_suffix(".tmp")
                with open(temp, "w") as f:
                    json.dump(data, f, indent=2)
                temp.replace(self.results_file)

