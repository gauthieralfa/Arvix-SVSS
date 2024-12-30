import socket
import time
import threading
import hashlib
import rsa
import base64
import jpysocket
from cryptography import x509
from OpenSSL import crypto,SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from utils import generate_keys_car,generate_keys,get_certificate,sign,verifsign,get_certificate_der,receivestring,receiveint,receive_bytes_with_length,sendstring,send_bytes_with_length

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
num_ports = 1
PORTS = [60000 + i for i in range(0, 0 + num_ports)]  # Port to listen on (non-privileged ports are > 1023)
dict={}

class server(object):

    def __init__(self, hostname, ports):
        global dict
        self.hostname = hostname
        self.ports = ports
        self.sockets = []
        for port in ports:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print("port :"+str(port))
            self.socket.bind((self.hostname, port))
            self.socket.listen()
            print("Car ready at port "+str(port))
            self.sockets.append(self.socket)

            # Start a thread to handle incoming connections on this socket
            thread = threading.Thread(target=self.accept_connections, args=(self.socket,port))
            thread.start()

    def accept_connections(self,socket,port_dst):
        while True:
            clientsocket, (ip,port) = socket.accept()
            newthread = ClientThread(ip ,port , clientsocket,port_dst)
            newthread.start()


class ClientThread(threading.Thread):

    def __init__(self, ip, port, clientsocket,port_dst):

        print("connection from",ip)
        print("connection from port",port)
        self.ip = ip
        self.dst_port=port_dst
        print("connection on port (dst port)"+str(port_dst))
        self.port = port
        self.clientsocket = clientsocket
        self.server = server
        threading.Thread.__init__(self)

    def close(self):
        self.clientsocket.close()
        print("Thread",threading.get_ident(),":connection from",self.ip,"ended\n")

    def receive(self):
        recv=self.clientsocket.recv(1024)
        return recv

    def send_text(self,datas):
        self.clientsocket.send(datas.encode())

    def send_text_java(self,datas):
        msg=jpysocket.jpyencode(datas)
        self.clientsocket.sendall(msg)


## BEGINNING OF THE CODE



    def AT_Contract(self):
        global dict
        print("AT_Contract_Function")
        num_session = receiveint(self)
        C_AT = receive_bytes_with_length(self)
        print(C_AT)
        Contract_BD = receive_bytes_with_length(self)
        Sigma_AT_SUB_REQ = receive_bytes_with_length(self)
        Nonce_SesKVeh = receive_bytes_with_length(self)
        dict[num_session] = {}
        dict[num_session]["Contract_BD"] = Contract_BD

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
        print("BD_uc_uo Decrypted:\n"+BD_uc_uo)

        res=verifsign(certificate_sp,Contract_BD,BD_uc_uo.encode())
        #BD_uc_uo is the first part of AT. It has to be separated. 
        h_BD_uc_uo=hashlib.sha256((BD_uc_uo.encode())).hexdigest()
        print("HASH IS : "+h_BD_uc_uo)
        Sigma_AT_SUB_ACK_data=ID_BD+ID_AT+h_BD_uc_uo
        print("Sigma_AT_SUB_ACK_data: "+str(Sigma_AT_SUB_ACK_data))
        Sigma_AT_SUB_ACK=sign(Sigma_AT_SUB_ACK_data.encode(),private_key_car)
        

        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port_sp=self.dst_port-10000
        print("port dst to the reply car is "+str(port_sp))
        sock2.connect(('127.0.0.1',port_sp))
        print("LOCAL PORT SENT TO THE SP is:"+str(num_session))
        sendstring(sock2,"step_A4")
        sock2.sendall(num_session.to_bytes(4,byteorder='big'))
        send_bytes_with_length(sock2,Sigma_AT_SUB_ACK)
        send_bytes_with_length(sock2,h_BD_uc_uo.encode())
        print("HASH SENT")
        print("END of STEP 1/3")



    def open_the_car(self):

        
        Sigma_CR_AC_REQ64 = receivestring(self)
        Sigma_CR_AC_REQ=base64.b64decode(Sigma_CR_AC_REQ64)
        challenge_uc=receivestring(self)
        print("challenge received : "+challenge_uc)
        ID_UC=receivestring(self)
        hContractBD=receivestring(self)
        certificate_customer=get_certificate("cert_customer")
        cert_uc_bytes=self.clientsocket.recv(4096)
        #h_cert_uc_calc=hashlib.sha256((cert_uc)).hexdigest()
        #print("h_cert_uc_calc calculated : "+str(h_cert_uc_calc))
        # par exemple : cert_bytes = file.read()

        # Charger le certificat à partir des bytes
        cert_uc = x509.load_der_x509_certificate(cert_uc_bytes, backend=default_backend())

        # Extraire la clé publique du certificat
        public_key = cert_uc.public_key()


        res=verifsign(public_key,Sigma_CR_AC_REQ,challenge_uc+"\n"+ID_UC+"\n"+hContractBD);       
        print("Signature challenge checked")
        Contract_BD=dict[int(ID_UC)]["Contract_BD"] #Getting Contract_BD received by the SP
        hContractBD_prime=hashlib.sha256((Contract_BD)).hexdigest()
        if hContractBD==hContractBD_prime:
            print("HASH is VALID")
        else:
            print("INVALID HASH, CAR NOT OPEN")
        #LATER ... Sigma_CR_AC_GRANTED=sign(ID_BD+ID_AT,private_key_car) with data from ID_UC instead of port.
        print("END OF STEP 3/3")



    def run(self):
        print("Thread",threading.get_ident(),"started")
        step=receivestring(self)
        if step=="AT_Contract":
            self.AT_Contract()
        elif step=="open":
            self.open_the_car() 


private_key_sp,public_key, private_key_sp_pem=generate_keys() #Generation of the keys
private_key_car,public_key, private_key_car_pem=generate_keys_car() #Generation of the keys
 #SEVER IS NOW READY
server(HOST,PORTS)