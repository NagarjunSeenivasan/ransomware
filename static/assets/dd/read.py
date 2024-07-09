
import os
import base64
import pandas as pd
import numpy as np
import csv

dat1 = pd.read_csv('static/graph/data.csv')
dat=dat1.head(1600)
data=[]
i=0
for ss in dat.values:
    dt=[]
    
    sf=ss[0]
    sf1=sf.split("|")
    sf2=len(sf1)
    for sf2 in sf1:
        dt.append(sf2)
    data.append(dt)
    


with open('static/graph/data2.csv','w',newline='') as outfile:
    writer = csv.writer(outfile, quoting=csv.QUOTE_NONNUMERIC)
    #writer.writerow(col[0] for col in mycursor.description)
    for row in data:
        
        writer.writerow(row)
