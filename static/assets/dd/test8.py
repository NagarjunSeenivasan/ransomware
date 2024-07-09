import subprocess

driveStr = subprocess.check_output("fsutil fsinfo drives")
###driveStr = driveStr.strip().lstrip('Drives: ')
###drives = driveStr.split()
drv=driveStr.decode(encoding='utf-8')
#print(drv)
drv1=drv.split('Drives: ')
drv2=drv1[1].split(' ')
#print(drv2)
for rr in drv2:
    print(rr)
