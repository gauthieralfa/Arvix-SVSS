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
from Crypto.Signature import PKCS1_v1_5
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
import time



BD_uc_uo=b''
Sigma_AT_SUB_REQ=b''
C_AT=b''
Nonce_SesKVeh=b''

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 50010    # Port to listen on (non-privileged ports are > 1023)
server_reference_path = "keys/"

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

def get_certificate_der(certif_file):
    file= open("all_keys/"+certif_file, "rb")
    certificate_der = file.read()
    file.close()
    return certificate_der



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
    #pri = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)
    #prikey = rsa.PrivateKey.load_pkcs1(pri, 'DER')
    data = rsa.decrypt(base64.b64decode(message), key)
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
        print("Service provider ready")
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

    def receive(self):
        #time.sleep(0.1)
        recv=self.clientsocket.recv(1024)

        return recv

    def send_text(self,datas):
        print("Thread",threading.get_ident(),":sending file:",datas)
        self.clientsocket.sendall(datas.encode())
        print("Thread",threading.get_ident(),":file sent")
        #self.close()
        
    def send_json(self,sock,data_list):
        print("Thread",threading.get_ident(),":sending json:",data_list)
        json_data= json.dumps(data_list, ensure_ascii=False).encode('gbk')
        encoded_json_data = json_data.encode('utf-8')
        print("data send: "+str(json_data))
        #sock.sendall(socket.htonl(data_length).to_bytes(4, byteorder='big'))
        sock.send(json_data)
        print("Thread",threading.get_ident(),":file sent")
        #self.close()

    def send_text_java(self,datas):
        ##print("Thread",threading.get_ident(),":sending text java:",datas)
        msg=jpysocket.jpyencode(datas)
        self.clientsocket.sendall(msg)
        ##print("Thread",threading.get_ident(),":sending msg java:",msg)
        #self.close()
        


    def send_text2(self,datas):
        ##print("Thread",threading.get_ident(),":sending file:",datas)
        self.clientsocket.send(datas.encode())
        ##print("Thread",threading.get_ident(),":file sent")

    def send_object(self,datas):
        print("Thread",threading.get_ident(),":sending object")
        self.clientsocket.sendall(datas)
        ##print("Thread",threading.get_ident(),":object sent")
        #self.close()



    def reservation(self):
        ##
        ##global session_key
        global BD_uc_uo
        global C_AT
        global Sigma_AT_SUB_REQ
        global Nonce_SesKVeh 
        global ID_BD
        global ID_AT
        global start_time_A1

        #STEP A1: Reception of BD_uc_uo
        print("---PHASE 1 ---\n")
        print("---Reception of BD_uo_uc from the Customer ---\n")
        start_time_A1 = time.time()
        certificate_customer=get_certificate_der("cert_customer.der")
    
        BD_uc_uo=self.receive()
        BD_uc_uo_string=BD_uc_uo.decode()
        h_cert_uc=BD_uc_uo_string.splitlines()[4]
        print("\nh_cert_uc received is: "+h_cert_uc)
        h_cert_uc_calc=hashlib.sha256((certificate_customer)).hexdigest()
        print("\nh_cert_uc_calculated is: "+h_cert_uc_calc)
        print("BD_uc_uo received is :\n"+BD_uc_uo_string) #To DELETE
        self.send_text_java("BD_uc_uo received")
        print("\nBD_uc_uo well received\n")
        Contract_BD=sign(BD_uc_uo,private_key_sp_pem)
        print("\n----Contract_BD has ben done by signing BD_uc_uo with the SP Private key---")
        


        ##STEP A2:
        ID_BD=BD_uc_uo_string.splitlines()[0]
        ID_AT=str(random.randint(1, 1000))
        print("\nID_AT is generated randomly: "+ID_AT)
        AT=ID_BD+"\n"+BD_uc_uo_string+ID_AT
        print("\nAT is: \n"+AT)


        Nonce_SesKVeh =b'150000'
        Kveh64 =b'HEaV63ebUEAjib07VBqK3/HRq0q/u4y1mLNULYzZgI0='
        Kveh=base64.b64decode(Kveh64)
        Ses_KVeh=PBKDF2(Nonce_SesKVeh,Kveh,32,count=1000)
        #print("\nOutput of Ses_Kveh:"+str(Ses_KVeh))

        Ses_KVeh64=base64.b64encode(Ses_KVeh)
        f = Fernet(Ses_KVeh64)
        C_AT=f.encrypt(AT.encode())
        print("\nAccess Token: "+str(C_AT))
     
        Sigma_AT_SUB_REQ=sign(C_AT+Nonce_SesKVeh,private_key_sp_pem)
        print("\nSigma_AT_SUB_REQ signed")




        'SEND_TO_THE_CAR'

        #CONNECTION WITH THE CAR
        print("\nConnection with the CAR")
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect(('127.0.0.1',50020))
        sock2.send("AT_Contract".encode())
        ACK=sock2.recv(1024)
        sock2.send(C_AT)
        ACK=sock2.recv(1024)
        sock2.send(Contract_BD)
        ACK=sock2.recv(1024)
        sock2.send(Sigma_AT_SUB_REQ)
        ACK=sock2.recv(1024)
        sock2.send(Nonce_SesKVeh)
        ACK=sock2.recv(1024)
        return BD_uc_uo,Sigma_AT_SUB_REQ,C_AT,Nonce_SesKVeh
 

    def step_A4(self):
        
        global BD_uc_uo
        global C_AT
        global Sigma_AT_SUB_REQ
        global Nonce_SesKVeh 
        global Sigma_AT_SUB_ACK
        global h_BD_uc_uo

        'RECEIVE FROM THE CAR'
        Sigma_AT_SUB_ACK = self.receive()
        self.send_text2("\nSigma_AT_SUB_ACK Received")
        h_BD_uc_uo = self.receive()
        print("\nh_BD_uc_uo Received : "+h_BD_uc_uo.decode())
        self.send_text2("h_BD_uc_uo Received :")

        h_BD_uc_uo_prime=hashlib.sha256((BD_uc_uo)).hexdigest()
        if h_BD_uc_uo_prime==h_BD_uc_uo.decode():
            print("h_BD_uc_uo CHECKED AND OK")
        else:
            print("h_BD_uc_uo FAIL VERIFICATION")
        certificate_car=get_certificate("cert_car.crt")
        Sigma_AT_SUB_ACK_data=ID_BD+ID_AT+h_BD_uc_uo.decode()
        print("Sigma_AT_SUB_ACK_data: "+Sigma_AT_SUB_ACK_data)
        res=verifsign(certificate_car,Sigma_AT_SUB_ACK,Sigma_AT_SUB_ACK_data.encode())
        print("Sigma_AT_SUB_ACK Verified Successfully")
        print("\n\n--- time of Step A1 to A4 ---: %s" % (time.time() - start_time_A1))
        
        #CONNECTION WITH THE PORTABLE AGAIN



    def updated_step(self):
        global ID_BD
        global ID_AT

        print("Sigma_AT_SUB_ACK SENT : "+str(Sigma_AT_SUB_ACK))
        ACK=self.receive()
        print("ACK is : "+str(ACK))

        ## Sending Sigma_AT_SUB_ACK

        size = len(Sigma_AT_SUB_ACK)
        print("File bytes:", size)
        self.clientsocket.sendall(size.to_bytes(4, byteorder='big')) #Taille des bytes
        ACK=self.receive()
        print("received: "+str(ACK))
        self.clientsocket.sendall(Sigma_AT_SUB_ACK) #Envoi de la signature en Byte

        ACK=self.receive()

        ## Sending h_BD_uc_uo
        size = len(h_BD_uc_uo)
        print("File bytes:", size)
        self.clientsocket.sendall(size.to_bytes(4, byteorder='big')) #Taille des bytes
        ACK=self.receive()
        print("received: "+str(ACK))
        self.clientsocket.sendall(h_BD_uc_uo) #Envoi de la signature en Byte

        ACK=self.receive()

        ID_BD_ID_AT=str(ID_BD)+"\n"+str(ID_AT)
        size = len(ID_BD_ID_AT)
        print("File bytes:", size)
        self.clientsocket.sendall(size.to_bytes(4, byteorder='big')) #Taille des bytes
        ACK=self.receive()
        print("received: "+str(ACK))
        self.clientsocket.sendall(ID_BD_ID_AT.encode()) #Envoi de la signature en Byte



    def run(self):
        
        #time.sleep(10**-3)
        print("Thread",threading.get_ident(),"started")
        step=self.receive()
        ##print(step)
        ##print("registration".encode())
        self.send_text_java("OK")
        if step=="registration".encode():
            self.registration()
        elif step=="reservation".encode():
            self.reservation()
        elif step=="reception".encode():
            self.send_to_customer()
        elif step=="step_A4".encode():
            self.step_A4()
        elif step=="updated_step".encode():
            self.updated_step()



private_key_sp,public_key, private_key_sp_pem=generate_keys() #Generation of the keys
private_key_car,public_key, private_key_car_pem=generate_keys_car() #Generation of the keys
#cert=create_certificate(key) #Creattion of the certificate for public keys
print("Keys generated ready") #SEVER IS NOW READY
server(HOST,PORT)
