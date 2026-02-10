import psutil

def kill_process_by_path(path):
    for proc in psutil.process_iter(['pid', 'exe']):
        try:
            if proc.info['exe'] and path in proc.info['exe']:
                proc.kill()
                return True
        except:
            pass
    return False
