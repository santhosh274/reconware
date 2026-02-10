import os
import stat

def lock_file(path):
    try:
        os.chmod(path, stat.S_IREAD)
        return True
    except:
        return False
