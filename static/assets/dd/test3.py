import os
import subprocess

driveStr = subprocess.check_output("fsutil fsinfo drives")
drv=driveStr.decode(encoding='utf-8')
drv1=drv.split('Drives: ')
drv2=drv1[1].split(' ')
dlen=len(drv2)
i=0
for rr in drv2:
    print(rr)
    dr=rr+"wamp\www"
    if os.path.isdir(dr):
        print(dr)
        break

'''
    rootdir = rr
    for file in os.listdir(rootdir):
        d = os.path.join(rootdir, file)
        
        if os.path.isdir(d):
            print("dir="+d)
            #print(os.path.basename(d))
        else:
            print(d)'''
