import shutil
import time
import os
import json
import base64
from pathlib import Path
from typing import Optional, Tuple
from .process_killer import kill_ransomware_processes, get_process_using_file

QUARANTINE_DIR = Path("./quarantine")
QUARANTINE_DIR.mkdir(exist_ok=True)

QUARANTINE_METADATA = QUARANTINE_DIR / "quarantine_metadata.json"

ENCRYPTION_KEY = b"ReconWare_Qarantine_Secure_2026"

def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using XOR cipher"""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def quarantine_file(file_path: Path, max_retries: int = 3, retry_delay: float = 0.5) -> Tuple[bool, str]:
    if not file_path.exists():
        return False, f"File does not exist: {file_path}"
    
    if not file_path.is_file():
        return False, f"Path is not a file: {file_path}"
    
    processes = get_process_using_file(str(file_path))
    
    if processes:
        print(f"[Quarantine] File {file_path} is being used by {len(processes)} process(es)")
        for proc in processes:
            print(f"  - PID {proc['pid']}: {proc['name']} ({proc['cmdline'][:50]}...)")
        
        success, killed_pids, message = kill_ransomware_processes(str(file_path))
        
        if success:
            print(f"[Quarantine] Killed processes: {killed_pids}")
            time.sleep(0.5)
        else:
            print(f"[Quarantine] Could not kill processes: {message}")
    
    for attempt in range(max_retries):
        try:
            dest = QUARANTINE_DIR / file_path.name
            counter = 1
            while dest.exists():
                dest = QUARANTINE_DIR / f"{file_path.stem}_{counter}{file_path.suffix}"
                counter += 1
            
            # Read original file content
            with open(file_path, 'rb') as f:
                original_data = f.read()
            
            # Encrypt the file content
            encrypted_data = _xor_encrypt(original_data, ENCRYPTION_KEY)
            
            # Write encrypted content to quarantine with .quar extension
            encrypted_dest = QUARANTINE_DIR / f"{dest.stem}.quar"
            counter = 1
            while encrypted_dest.exists():
                encrypted_dest = QUARANTINE_DIR / f"{dest.stem}_{counter}.quar"
                counter += 1
            
            with open(encrypted_dest, 'wb') as f:
                f.write(encrypted_data)
            
            # Delete original file
            file_path.unlink()
            
            _log_quarantine(file_path, encrypted_dest)
            
            return True, f"Successfully quarantined and encrypted to: {encrypted_dest}"
            
        except PermissionError as e:
            if attempt < max_retries - 1:
                print(f"[Quarantine] File locked, retrying ({attempt + 1}/{max_retries})...")
                time.sleep(retry_delay)
                continue
            else:
                return False, f"File is locked by another process after {max_retries} attempts"
                
        except Exception as e:
            return False, f"Quarantine failed: {str(e)}"
    
    return False, "Quarantine failed after all retries"


def restore_file(quarantine_name: str, destination: Path) -> Tuple[bool, str]:
    quarantine_path = QUARANTINE_DIR / quarantine_name
    
    if not quarantine_path.exists():
        return False, f"Quarantined file not found: {quarantine_name}"
    
    try:
        # Read encrypted content
        with open(quarantine_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt content
        decrypted_data = _xor_encrypt(encrypted_data, ENCRYPTION_KEY)
        
        # Ensure destination directory exists
        destination.parent.mkdir(parents=True, exist_ok=True)
        
        # If destination exists, remove it first
        if destination.exists():
            destination.unlink()
        
        # Write decrypted content
        with open(destination, 'wb') as f:
            f.write(decrypted_data)
        
        # Remove encrypted quarantine file
        quarantine_path.unlink()
        
        return True, f"Successfully restored to: {destination}"
        
    except Exception as e:
        return False, f"Restore failed: {str(e)}"


def list_quarantined_files() -> list:
    files = []
    
    if not QUARANTINE_DIR.exists():
        return files
    
    for f in QUARANTINE_DIR.iterdir():
        if f.is_file() and f.suffix == '.quar':
            stat = f.stat()
            files.append({
                "name": f.name,
                "size": stat.st_size,
                "quarantine_time": stat.st_ctime,
                "path": str(f)
            })
    
    return files


def _log_quarantine(original_path: Path, quarantine_path: Path):
    from datetime import datetime
    
    metadata_file = QUARANTINE_DIR / "quarantine_metadata.json"
    
    try:
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
        else:
            metadata = {"quarantined_files": []}
    except:
        metadata = {"quarantined_files": []}
    
    entry = {
        "original_path": str(original_path),
        "quarantine_path": str(quarantine_path),
        "timestamp": datetime.now().isoformat(),
        "filename": original_path.name,
        "file_type": original_path.suffix.lower(),
        "encrypted": True
    }
    
    metadata["quarantined_files"].append(entry)
    
    try:
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    except Exception as e:
        print(f"[Quarantine] Failed to save metadata: {e}")


def delete_quarantined_file(quarantine_name: str) -> Tuple[bool, str]:
    quarantine_path = QUARANTINE_DIR / quarantine_name
    
    if not quarantine_path.exists():
        return False, f"Quarantined file not found: {quarantine_name}"
    
    try:
        quarantine_path.unlink()
        return True, f"Deleted quarantined file: {quarantine_name}"
    except Exception as e:
        return False, f"Delete failed: {str(e)}"


def get_quarantine_stats() -> dict:
    """Get statistics about quarantined files"""
    metadata_file = QUARANTINE_DIR / "quarantine_metadata.json"
    
    stats = {
        "total_files": 0,
        "by_type": {},
        "by_day": {},
        "total_size": 0
    }
    
    if metadata_file.exists():
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            files = metadata.get("quarantined_files", [])
            stats["total_files"] = len(files)
            
            for file_entry in files:
                file_type = file_entry.get("file_type", "unknown")
                stats["by_type"][file_type] = stats["by_type"].get(file_type, 0) + 1
                
                timestamp = file_entry.get("timestamp", "")
                if timestamp:
                    day = timestamp.split("T")[0]
                    stats["by_day"][day] = stats["by_day"].get(day, 0) + 1
            
            quarantine_dir = QUARANTINE_DIR
            if quarantine_dir.exists():
                for f in quarantine_dir.iterdir():
                    if f.is_file() and f.suffix == '.quar':
                        stats["total_size"] += f.stat().st_size
                        
        except Exception as e:
            print(f"[Quarantine] Error reading stats: {e}")
    
    return stats
