import psutil
import os
from typing import List, Tuple


def kill_process_by_path(file_path: str, force: bool = True) -> Tuple[bool, List[int]]:
    """
    Kill processes that are associated with the given file path.
    
    Args:
        file_path: Path to the file that the process is using
        force: If True, use SIGKILL (9), otherwise use SIGTERM (15)
    
    Returns:
        Tuple of (success: bool, killed_pids: List[int])
    """
    killed_pids = []
    
    for proc in psutil.process_iter(['pid', 'exe', 'name', 'cmdline']):
        try:
            proc_info = proc.info
            
            # Check if process executable matches the path
            exe = proc_info.get('exe', '')
            cmdline = proc_info.get('cmdline', [])
            
            # Check various ways the file could be referenced
            file_path_normalized = os.path.normpath(file_path).lower()
            
            is_target_process = False
            
            # Check executable path
            if exe and file_path_normalized in exe.lower():
                is_target_process = True
            
            # Check command line arguments
            if cmdline:
                for arg in cmdline:
                    if arg and file_path_normalized in arg.lower():
                        is_target_process = True
                        break
            
            if is_target_process:
                pid = proc_info['pid']
                try:
                    if force:
                        proc.kill()
                    else:
                        proc.terminate()
                    killed_pids.append(pid)
                    print(f"[ProcessKiller] Killed process {pid} ({proc_info.get('name', 'unknown')}) for file: {file_path}")
                except psutil.NoSuchProcess:
                    print(f"[ProcessKiller] Process {pid} already terminated")
                except psutil.AccessDenied:
                    print(f"[ProcessKiller] Access denied to kill process {pid}")
                except Exception as e:
                    print(f"[ProcessKiller] Error killing process {pid}: {e}")
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            print(f"[ProcessKiller] Error iterating processes: {e}")
    
    return len(killed_pids) > 0, killed_pids


def kill_process_by_name(process_name: str, force: bool = True) -> Tuple[bool, List[int]]:
    """
    Kill all processes with the given name.
    
    Args:
        process_name: Name of the process (e.g., 'python.exe', 'notepad.exe')
        force: If True, use SIGKILL, otherwise use SIGTERM
    
    Returns:
        Tuple of (success: bool, killed_pids: List[int])
    """
    killed_pids = []
    process_name_lower = process_name.lower()
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() == process_name_lower:
                pid = proc.info['pid']
                try:
                    if force:
                        proc.kill()
                    else:
                        proc.terminate()
                    killed_pids.append(pid)
                    print(f"[ProcessKiller] Killed process {pid} ({process_name})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return len(killed_pids) > 0, killed_pids


def kill_parent_and_children(pid: int, force: bool = True) -> Tuple[bool, List[int]]:
    """
    Kill a process and all its children.
    
    Args:
        pid: Process ID to kill
        force: If True, use SIGKILL, otherwise use SIGTERM
    
    Returns:
        Tuple of (success: bool, killed_pids: List[int])
    """
    killed_pids = []
    
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        
        # First kill all children
        for child in children:
            try:
                if force:
                    child.kill()
                else:
                    child.terminate()
                killed_pids.append(child.pid)
                print(f"[ProcessKiller] Killed child process {child.pid}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Then kill parent
        try:
            if force:
                parent.kill()
            else:
                parent.terminate()
            killed_pids.append(pid)
            print(f"[ProcessKiller] Killed parent process {pid}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    except psutil.NoSuchProcess:
        print(f"[ProcessKiller] Process {pid} not found")
    except psutil.AccessDenied:
        print(f"[ProcessKiller] Access denied to process {pid}")
    except Exception as e:
        print(f"[ProcessKiller] Error killing process tree {pid}: {e}")
    
    return len(killed_pids) > 0, killed_pids


def get_process_using_file(file_path: str) -> List[dict]:
    """
    Get information about all processes using a specific file.
    
    Args:
        file_path: Path to the file
    
    Returns:
        List of process info dictionaries
    """
    processes = []
    file_path_normalized = os.path.normpath(file_path).lower()
    
    for proc in psutil.process_iter(['pid', 'exe', 'name', 'cmdline']):
        try:
            proc_info = proc.info
            exe = proc_info.get('exe', '')
            cmdline = proc_info.get('cmdline', [])
            
            is_using = False
            
            # Check executable path
            if exe and file_path_normalized in exe.lower():
                is_using = True
            
            # Check command line arguments
            if cmdline:
                for arg in cmdline:
                    if arg and file_path_normalized in arg.lower():
                        is_using = True
                        break
            
            if is_using:
                processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info.get('name', 'unknown'),
                    'exe': exe,
                    'cmdline': ' '.join(cmdline) if cmdline else ''
                })
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return processes


def kill_ransomware_processes(file_path: str) -> Tuple[bool, List[int], str]:
    """
    Comprehensive function to kill ransomware processes.
    First tries to kill processes using the file, then tries to kill parent processes.
    
    Args:
        file_path: Path to the suspicious file
    
    Returns:
        Tuple of (success: bool, killed_pids: List[int], message: str)
    """
    # First, get processes using the file
    processes = get_process_using_file(file_path)
    
    if not processes:
        return False, [], f"No processes found using file: {file_path}"
    
    killed_pids = []
    
    # Try to kill each process and its parent tree
    for proc_info in processes:
        pid = proc_info['pid']
        success, pids = kill_parent_and_children(pid, force=True)
        if success:
            killed_pids.extend(pids)
    
    if killed_pids:
        return True, killed_pids, f"Successfully killed {len(killed_pids)} process(es)"
    
    return False, [], "Failed to kill processes (may require elevated privileges)"

