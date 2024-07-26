import multiprocessing
import socket
import time
import threading
import os
import random
import hashlib
import rsa
import json
import base64
import jpysocket
from OpenSSL import crypto,SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import hmac
import codecs
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 50020  # Port to listen on (non-privileged ports are > 1023)
server_reference_path = "car1/"

'''
key = Fernet.generate_key()
masterkey = os.urandom(32)
file=open(server_reference_path+"keycar1.txt",'wb')
file.write(key)
file.close()
file=open(server_reference_path+"masterkeycar1.txt",'wb')
file.write(masterkey)
file.close()
'''
IdCar="206"

def generate_keys_Obsolete():
    key=crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    file1 = open("car1/priv_s.txt", 'wb')
    file1.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
    file1.close()
    file2 = open("car1/pub_s.txt", 'wb')
    file2.write(crypto.dump_publickey(crypto.FILETYPE_PEM,key))
    file2.close()
    return key

def generate_keys():
    #USE FOR SIGNATURE WITH PYTHON - Update : Not used right now. 
    file1 = open("all_keys/priv_sp.pem")
    priv_key=file1.read()
    private_key_sp_pem=crypto.load_privatekey(crypto.FILETYPE_PEM, priv_key)
    file1.close()

    #NEVER USE, Certificate is used instead of public key in python - Update : Use Get Certificate instead
    file2 = open("all_keys/pub_spPKCS1.pem")
    pub_key=file2.read()
    public_key=rsa.PublicKey.load_pkcs1(pub_key)
    file2.close()

    #USE FOR DECRYPT WITH PYTHON - Update : Use for Signature
    file3 = open("all_keys/priv_sp.txt","rb")
    priv_key=file3.read()
    private_key_sp=rsa.PrivateKey.load_pkcs1(priv_key,'DER')
    file3.close()
    return private_key_sp,public_key,private_key_sp_pem


def generate_keys_car():
    #USE FOR SIGNATURE WITH PYTHON - Update : Not used right now. 
    file1 = open("all_keys/priv_car.key")
    priv_key=file1.read()
    private_car_sp=crypto.load_privatekey(crypto.FILETYPE_PEM, priv_key)
    file1.close()

    #NEVER USE, Certificate is used instead of public key in python - Update : Use Get Certificate instead
    file2 = open("all_keys/pub_spPKCS1.pem")
    pub_key=file2.read()
    public_key=rsa.PublicKey.load_pkcs1(pub_key)
    file2.close()

    #USE FOR DECRYPT WITH PYTHON - Update : Use for Signature
    file3 = open("all_keys/priv_sp.txt","rb")
    priv_key=file3.read()
    private_key_car_pem=rsa.PrivateKey.load_pkcs1(priv_key,'DER')
    file3.close()
    return private_car_sp,public_key,private_key_car_pem

def create_certificate(key):
    cert=crypto.X509()
    cert.set_pubkey(key)
    cert.get_subject().ST = "Sweden"
    cert.get_subject().L = "Stockholm"
    cert.get_subject().O = "Service Provider"
    cert.get_subject().OU = "SharingCar"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.get_subject().CN = "test"
    cert.sign(key,"sha256")
    file1=open("certs/cert_s",'wb')
    file1.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    file1.close()
    return cert

def get_certificate(certif_file):
    file= open("all_keys/"+certif_file, "r")
    certificate_str = file.read()
    file.close()
    certificate=crypto.load_certificate(crypto.FILETYPE_PEM,certificate_str)
    return certificate

def sign(message,key):
    signature=crypto.sign(key,message,"sha256")
    return signature

def verifsign(certificate,signature,data):
    verif=crypto.verify(certificate,signature,data,"sha256")
    return verif

def encrypt(certificat,message):
    pub = crypto.dump_publickey(crypto.FILETYPE_PEM, certificat.get_pubkey())
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pub)
    data = rsa.encrypt(message.encode(), pubkey)
    data = base64.b64encode(data)
    return data

def decrypt(key,message):
    pri = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)
    prikey = rsa.PrivateKey.load_pkcs1(pri, 'DER')
    data = rsa.decrypt(base64.b64decode(message), prikey)
    return data


def encrypt_aead(key,message,auth_data):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, message, auth_data)
    encrypted64=base64.b64encode(nonce+encrypted)
    return encrypted64

def decrypted_aead(key,ciphered,auth_data):
    nonce=nonce=ciphered[0:12]
    data_enc=data=ciphered[12:]
    aesgcm = AESGCM(key)
    decrypted=aesgcm.decrypt(nonce, data_enc, auth_data)
    return decrypted


class server(object):

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.hostname, self.port))
        self.socket.listen()
        print("Car ready at port 50001")
        while True:
            clientsocket, (ip,port) = self.socket.accept()
            newthread = ClientThread(ip ,port , clientsocket,self)
            newthread.start()


class ClientThread(threading.Thread):

    def __init__(self, ip, port, clientsocket,server):

        print("connection from",ip)
        self.ip = ip
        self.port = port
        self.clientsocket = clientsocket
        self.server = server
        threading.Thread.__init__(self)

    def close(self):

        self.clientsocket.close()
        print("Thread",threading.get_ident(),":connection from",self.ip,"ended\n")

    def receive2(self,m):
        size=self.clientsocket.recv(1024)
        self.clientsocket.send("OK".encode())
        print("Thread",threading.get_ident(),":receiving file:",m)
        recv=self.clientsocket.recv(1024*1024)
        while (len(recv)!=int(size)):
            recv+=self.clientsocket.recv(1024*1024)
        file = open(server_reference_path+"m",'wb')
        file.write(recv)
        file.close()
        print("Thread",threading.get_ident(),":file received")
        #self.close()
        #return m

    def receive(self):
        recv=self.clientsocket.recv(1024)
        #print("Thread",threading.get_ident(),":receiving file:",recv.decode())
        return recv

    def receive_byte(self):
        recv=self.clientsocket.recv(1024)
        #print("Thread",threading.get_ident(),":receiving file:",recv)
        return recv

    def send_text(self,datas):
        ##print("Thread",threading.get_ident(),":sending file:",datas)
        self.clientsocket.send(datas.encode())
        ##print("Thread",threading.get_ident(),":file sent")

    def send_text_java(self,datas):
        ##print("Thread",threading.get_ident(),":sending text java:",datas)
        msg=jpysocket.jpyencode(datas)
        self.clientsocket.sendall(msg)
        ##print("Thread",threading.get_ident(),":sending msg java:",msg)
        #self.close()

    def send_object(self,datas):
        ##print("Thread",threading.get_ident(),":sending object")
        self.clientsocket.sendall(datas)
        ##print("Thread",threading.get_ident(),":object sent")






    def AT_Contract(self):
        print("AT_Contract_Function")
        C_AT = self.receive()
        print(C_AT)
        self.send_text("OK")
        Contract_BD = self.receive()
        self.send_text("OK")
        Sigma_AT_SUB_REQ = self.receive()
        self.send_text("OK")
        Nonce_SesKVeh = self.receive()
        self.send_text("OK")


        certificate_customer=get_certificate("cert_customer")
        certificate_sp=get_certificate("cert_sp")
        res=verifsign(certificate_sp,Sigma_AT_SUB_REQ,C_AT+Nonce_SesKVeh)
        Kveh64 =b'HEaV63ebUEAjib07VBqK3/HRq0q/u4y1mLNULYzZgI0='
        Kveh=base64.b64decode(Kveh64)
        Ses_KVeh=PBKDF2(Nonce_SesKVeh,Kveh,32,count=1000)
        Ses_KVeh64=base64.b64encode(Ses_KVeh)
        f = Fernet(Ses_KVeh64)
        AT=f.decrypt(C_AT)
        print("C_AT Decrypted:\n"+AT.decode())
        ID_BD=AT.decode().splitlines()[0]
        ID_AT=AT.decode().splitlines()[7]
        print("ID_AT is: "+ID_AT)
        BD_UC_uo_tmp = AT.decode().splitlines()[1:7]
        BD_uc_uo = "\n".join(BD_UC_uo_tmp) + "\n"
        #BD_uc_uo=AT.splitlines()[1]+"\n".encode()+AT.splitlines()[2]+"\n".encode()+AT.splitlines()[3]+"\n".encode()+AT.splitlines()[4]+"\n".encode()+AT.splitlines()[5]+"\n".encode()+AT.splitlines()[6]+"\n".encode()
        print("BD_uc_uo Decrypted:\n"+BD_uc_uo)

        res=verifsign(certificate_sp,Contract_BD,BD_uc_uo.encode())
        #BD_uc_uo is the first part of AT. It has to be separated. 
        h_BD_uc_uo=hashlib.sha256((BD_uc_uo.encode())).hexdigest()
        print("HASH IS : "+h_BD_uc_uo)
        Sigma_AT_SUB_ACK_data=ID_BD+ID_AT+h_BD_uc_uo
        print("Sigma_AT_SUB_ACK_data: "+str(Sigma_AT_SUB_ACK_data))
        Sigma_AT_SUB_ACK=sign(Sigma_AT_SUB_ACK_data.encode(),private_key_car)
        

        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect(('127.0.0.1',50010))


        sock2.send("step_A4".encode())
        ACK=sock2.recv(1024)
        sock2.send(Sigma_AT_SUB_ACK)
        ACK=sock2.recv(1024)
        sock2.send(h_BD_uc_uo.encode())
        print("HASH SENT")
        ACK=sock2.recv(1024)



    def open_the_car(self):

        
        Sigma_Uc64 = self.receive()
        Sigma_Uc=base64.b64decode(Sigma_Uc64)
        #print("Sigma_Uc received : "+str(Sigma_Uc))
        self.send_text_java("OK")
        challenge_uc=self.receive()
        certificate_customer=get_certificate("cert_customer")
        print("challenge received : "+challenge_uc.decode())
        self.send_text_java("OK")
        cert_uc=self.receive()
        

        #print("cert_uc received : "+str(cert_uc))
        h_cert_uc_calc=hashlib.sha256((cert_uc)).hexdigest()
        print("h_cert_uc_calc calculated : "+str(h_cert_uc_calc))
        res=verifsign(certificate_customer,Sigma_Uc,challenge_uc)        
        print("Signature challenge checked")
        self.send_text_java("ACK")
        print("The CAR IS OPEN")



    def run(self):
        time.sleep(10**-3)
        print("Thread",threading.get_ident(),"started")
        step=self.receive()
        if step=="AT_Contract".encode():
            self.send_text("OK")
            self.AT_Contract()
        elif step=="open".encode():
            self.open_the_car() 


private_key_sp,public_key, private_key_sp_pem=generate_keys() #Generation of the keys
private_key_car,public_key, private_key_car_pem=generate_keys_car() #Generation of the keys
 #SEVER IS NOW READY
server(HOST,PORT)