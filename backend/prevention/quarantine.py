import os, shutil

def quarantine(path):
    qdir = "quarantine"
    os.makedirs(qdir, exist_ok=True)
    shutil.move(path, qdir)
