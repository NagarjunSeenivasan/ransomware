import os
import shutil

path="D:\soft"
for root, dirs, files in os.walk(path):  # replace the . with your starting directory
   for file in files:
      path_file = os.path.join(root,file)
      #shutil.copy2(path_file,'static/test') # change you destination dir
      print(path_file)
