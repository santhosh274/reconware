import os
import random
from pathlib import Path
from typing import List, Dict

class CanaryManager:
    """
    Manages 'canary' files used to detect ransomware activity.
    Highly sensitive files placed in monitored directories.
    If these files are modified, it's a strong indicator of ransomware.
    """
    
    CANARY_FILENAME_TEMPLATES = [
        ".audit_config_{id}.cfg",
        ".sys_backup_{id}.dat",
        "_____security_check_{id}_____.lock",
        ".vault_index_{id}.txt",
        ".metadata_cache_{id}.bin"
    ]
    
    def __init__(self, monitored_folders: List[str]):
        self.monitored_folders = [Path(f) for f in monitored_folders]
        self.canaries: Dict[str, Dict] = {} # path -> original_metadata
        
    def deploy_canaries(self):
        """Place hidden canary files in all monitored folders."""
        for folder in self.monitored_folders:
            if not folder.exists():
                continue
                
            # Create 2-3 canaries per folder
            num_canaries = random.randint(2, 3)
            for i in range(num_canaries):
                template = random.choice(self.CANARY_FILENAME_TEMPLATES)
                filename = template.format(id=random.randint(1000, 9999))
                canary_path = folder / filename
                
                try:
                    # Create the file with some random "valuable" looking content
                    content = f"ID: {random.getrandbits(64)}\nCHECKSUM: {random.getrandbits(32)}\nDO NOT MODIFY THIS FILE."
                    canary_path.write_text(content)
                    
                    # Make it hidden (Windows specific)
                    if os.name == 'nt':
                        os.system(f'attrib +h "{canary_path}"')
                    
                    stat = canary_path.stat()
                    self.canaries[str(canary_path)] = {
                        "original_size": stat.st_size,
                        "mtime": int(stat.st_mtime)
                    }
                    print(f"[Canary] Deployed: {canary_path}")
                except Exception as e:
                    print(f"[Canary] Failed to deploy at {canary_path}: {e}")

    def is_canary_file(self, file_path: str) -> bool:
        """Check if a given path is a managed canary file."""
        return file_path in self.canaries

    def check_canary_tampered(self, file_path: str) -> bool:
        """
        Check if a canary file has been modified or replaced.
        Modifying a canary is a high-confidence indicator of recursive encryption.
        """
        if file_path not in self.canaries:
            return False
            
        path = Path(file_path)
        if not path.exists():
            # If the canary was deleted, that's also suspicious
            return True
            
        try:
            stat = path.stat()
            original = self.canaries[file_path]
            
            # If size changed or modification time is significantly newer
            if stat.st_size != original["original_size"]:
                return True
            if int(stat.st_mtime) > original["mtime"]:
                return True
                
            return False
        except Exception:
            return True # Assume tampered if we can't check
