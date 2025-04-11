import os

def check_dir(dirPath):
    if os.path.exists(str(dirPath)):
        pass
    else:
        os.makedirs(dirPath)