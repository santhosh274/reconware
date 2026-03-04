import shutil
import time
import os
from pathlib import Path
from typing import Optional, Tuple
from .process_killer import kill_ransomware_processes, get_process_using_file

# Quarantine folder (outside watched directories to avoid loops)
QUARANTINE_DIR = Path("./quarantine")
QUARANTINE_DIR.mkdir(exist_ok=True)

# Metadata file for quarantine records
QUARANTINE_METADATA = QUARANTINE_DIR / "quarantine_metadata.json"


def quarantine_file(file_path: Path, max_retries: int = 3, retry_delay: float = 0.5) -> Tuple[bool, str]:
    """
    Move a file to quarantine and make it read-only.
    If file is locked by a process, attempts to kill the process first.
    
    Args:
        file_path: Path to the file to quarantine
        max_retries: Maximum number of retries if file is locked
        retry_delay: Delay between retries in seconds
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    # Validate path
    if not file_path.exists():
        return False, f"File does not exist: {file_path}"
    
    if not file_path.is_file():
        return False, f"Path is not a file: {file_path}"
    
    # Check if file is being used by any process
    processes = get_process_using_file(str(file_path))
    
    if processes:
        print(f"[Quarantine] File {file_path} is being used by {len(processes)} process(es)")
        for proc in processes:
            print(f"  - PID {proc['pid']}: {proc['name']} ({proc['cmdline'][:50]}...)")
        
        # Try to kill processes using the file
        success, killed_pids, message = kill_ransomware_processes(str(file_path))
        
        if success:
            print(f"[Quarantine] Killed processes: {killed_pids}")
            # Wait a bit for processes to fully terminate
            time.sleep(0.5)
        else:
            print(f"[Quarantine] Could not kill processes: {message}")
    
    # Try to quarantine with retries for locked files
    for attempt in range(max_retries):
        try:
            # Generate unique destination path
            dest = QUARANTINE_DIR / file_path.name
            counter = 1
            while dest.exists():
                dest = QUARANTINE_DIR / f"{file_path.stem}_{counter}{file_path.suffix}"
                counter += 1
            
            # Attempt to move the file
            shutil.move(str(file_path), str(dest))
            
            # Make the file read-only
            dest.chmod(0o400)
            
            # Log the quarantine
            _log_quarantine(file_path, dest)
            
            return True, f"Successfully quarantined to: {dest}"
            
        except PermissionError as e:
            # File is still locked
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
    """
    Restore a file from quarantine to its original location.
    
    Args:
        quarantine_name: Name of the quarantined file
        destination: Destination path for restoration
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    quarantine_path = QUARANTINE_DIR / quarantine_name
    
    if not quarantine_path.exists():
        return False, f"Quarantined file not found: {quarantine_name}"
    
    try:
        # Ensure destination directory exists
        destination.parent.mkdir(parents=True, exist_ok=True)
        
        # Move file back
        shutil.move(str(quarantine_path), str(destination))
        
        # Restore original permissions (read-write)
        destination.chmod(0o644)
        
        return True, f"Successfully restored to: {destination}"
        
    except Exception as e:
        return False, f"Restore failed: {str(e)}"


def list_quarantined_files() -> list:
    """
    List all files in quarantine.
    
    Returns:
        List of quarantined file information dictionaries
    """
    files = []
    
    if not QUARANTINE_DIR.exists():
        return files
    
    for f in QUARANTINE_DIR.iterdir():
        if f.is_file() and f.name != "quarantine_metadata.json":
            stat = f.stat()
            files.append({
                "name": f.name,
                "size": stat.st_size,
                "quarantine_time": stat.st_ctime,
                "path": str(f)
            })
    
    return files


def _log_quarantine(original_path: Path, quarantine_path: Path):
    """
    Log quarantine information to metadata file.
    """
    import json
    from datetime import datetime
    
    metadata_file = QUARANTINE_DIR / "quarantine_metadata.json"
    
    # Load existing metadata
    try:
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
        else:
            metadata = {"quarantined_files": []}
    except:
        metadata = {"quarantined_files": []}
    
    # Add new entry
    entry = {
        "original_path": str(original_path),
        "quarantine_path": str(quarantine_path),
        "timestamp": datetime.now().isoformat(),
        "filename": original_path.name
    }
    
    metadata["quarantined_files"].append(entry)
    
    # Save metadata
    try:
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    except Exception as e:
        print(f"[Quarantine] Failed to save metadata: {e}")


def delete_quarantined_file(quarantine_name: str) -> Tuple[bool, str]:
    """
    Permanently delete a quarantined file.
    
    Args:
        quarantine_name: Name of the quarantined file
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    quarantine_path = QUARANTINE_DIR / quarantine_name
    
    if not quarantine_path.exists():
        return False, f"Quarantined file not found: {quarantine_name}"
    
    try:
        quarantine_path.unlink()
        return True, f"Deleted quarantined file: {quarantine_name}"
    except Exception as e:
        return False, f"Delete failed: {str(e)}"

