import os

directory = "static"
#os.getcwd()
print(directory)

files = os.listdir(directory)
for f in files:
  print("I found a file called " + f)
