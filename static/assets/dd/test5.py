import os
import plyer
from pathlib import Path
from win32con import FILE_ATTRIBUTE_HIDDEN
from win32api import SetFileAttributes

current_dir =Path().resolve()
#Path().resolve()

def takefolder():  #Takes Folder Input
    while True:
        selected_folder = str(plyer.filechooser.choose_dir())
        selected_folder = selected_folder.replace("[", "")
        selected_folder = selected_folder.replace("]", "")
        selected_folder = selected_folder.replace("'", "")
        selected_folder = " ".join(selected_folder.split())
        if selected_folder=="":
            print("Please select a folder.")
        else:
            break
    return selected_folder

file_path = "D:/links.txt"
folder_path = os.path.join(current_dir, file_path)

if os.path.isdir(folder_path):
    final_path = folder_path
else:
    print("Please select the folder you want to hide!")
    final_path = takefolder()

try:    
    SetFileAttributes(final_path, FILE_ATTRIBUTE_HIDDEN)
    print("The folder is now hidden!")
except:
    print("No directory found.")
