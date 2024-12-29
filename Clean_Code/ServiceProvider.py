import socket
import time
import threading
import random
import hashlib
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
import time
import csv
from utils import generate_keys_car,generate_keys,get_certificate,sign,verifsign,get_certificate_der,receivestring,receiveint,sendstring,send_bytes_with_length,receive_bytes_with_length

dict={}

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)ID
num_ports = 1
PORTS = [50000 + i for i in range(0, 0 + num_ports)]  # Port to listen on (non-privileged ports are > 1023)


class server(object):

    def __init__(self, hostname, ports):
        self.hostname = hostname
        self.ports = ports
        self.sockets = []
        for port in ports:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print("port :"+str(port))
            self.socket.bind((self.hostname, port))
            self.socket.listen()
            print("Service provider ready")
            self.sockets.append(self.socket)

            # Start a thread to handle incoming connections on this socket
            thread = threading.Thread(target=self.accept_connections, args=(self.socket,port))
            # Creating the Thread by associating the socket and the port. 
            thread.start()
        
    def accept_connections(self,socket,port_dst):
        while True:
            clientsocket, (ip,port) = socket.accept()
            newthread = ClientThread(ip ,port , clientsocket,port_dst)
            newthread.start()


class ClientThread(threading.Thread):

    def __init__(self, ip, port, clientsocket,port_dst):
        global dict
        print("connection from",ip)
        print("connection from port (source port)",port)
        self.ip = ip
        self.dst_port=port_dst
        self.port=port
        print("connection on port (dst port)"+str(port_dst))
        self.clientsocket = clientsocket
        self.server = server
        self.BD_uc_uo=b''
        self.Sigma_AT_SUB_REQ=b''
        self.C_AT=b''
        self.Nonce_SesKVeh=b''
        self.ID_BD=''
        self.ID_AT=''
        self.start_time_A1 = time.time()
        threading.Thread.__init__(self)

    def close(self):
        self.clientsocket.close()
        print("Thread",threading.get_ident(),":connection from",self.ip,"ended\n")

    def receive(self):
        recv=self.clientsocket.recv(1024)
        return recv
        
    def send_text_java(self,datas):
        msg=jpysocket.jpyencode(datas)
        self.clientsocket.sendall(msg)

    def send_text2(self,datas):
        self.clientsocket.send(datas.encode())


## BEGINNING OF THE CODE



    def reservation(self):
        global dict

        #STEP A1: Reception of BD_uc_uo
        print("---PHASE 1 ---\n")
        print("---Reception of BD_uo_uc from the Customer ---\n")
        
        #PHRASE DE TEST
        certificate_customer=get_certificate_der("cert_customer.der")
        #Receiving Session Number
        self.session_number=receiveint(self)
        self.int_session_number = int(self.session_number)
        print("SESSION IS"+str(self.int_session_number))
        dict[self.int_session_number] = {}
        #End Receiving Session Number
        ##ENDING PHASE DE TEST



        self.BD_uc_uo=receivestring(self)
        BD_uc_uo_string=self.BD_uc_uo
        print("BD UC UO STRING IS:"+BD_uc_uo_string)
        h_cert_uc=BD_uc_uo_string.splitlines()[4]
        print("\nh_cert_uc received is: "+h_cert_uc)
        h_cert_uc_calc=hashlib.sha256((certificate_customer)).hexdigest()
        print("\nh_cert_uc_calculated is: "+h_cert_uc_calc)
        print("BD_uc_uo received is :\n"+BD_uc_uo_string) #To DELETE
        Contract_BD=sign(self.BD_uc_uo,private_key_sp_pem)
        print("\n----Contract_BD has ben done by signing BD_uc_uo with the SP Private key---")
        


        ##STEP A2:
        self.ID_BD=BD_uc_uo_string.splitlines()[0]
        self.ID_AT=str(random.randint(1, 1000))
        print("\nID_AT is generated randomly: "+self.ID_AT)
        AT=self.ID_BD+"\n"+BD_uc_uo_string+self.ID_AT
        print("\nAT is: \n"+AT)


        Nonce_SesKVeh =b'150000'
        Kveh64 =b'HEaV63ebUEAjib07VBqK3/HRq0q/u4y1mLNULYzZgI0='
        Kveh=base64.b64decode(Kveh64)
        Ses_KVeh=PBKDF2(Nonce_SesKVeh,Kveh,32,count=1000)

        Ses_KVeh64=base64.b64encode(Ses_KVeh)
        f = Fernet(Ses_KVeh64)
        C_AT=f.encrypt(AT.encode())
        print("\nAccess Token: "+str(C_AT))
     
        Sigma_AT_SUB_REQ=sign(C_AT+Nonce_SesKVeh,private_key_sp_pem)
        print("\nSigma_AT_SUB_REQ signed")




        'SEND_TO_THE_CAR'

        #CONNECTION WITH THE CAR
        print("\nConnection with the CAR")

        port_car=self.dst_port+10000
        print("port is "+str(port_car))
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect(('127.0.0.1',port_car))
        sendstring(sock2,"AT_Contract")

        sock2.sendall(self.session_number.to_bytes(4,byteorder='big')) #Sending_Num_Session. Replace by self_port without NAT. 
        send_bytes_with_length(sock2,C_AT)
        send_bytes_with_length(sock2,Contract_BD)
        send_bytes_with_length(sock2,Sigma_AT_SUB_REQ)
        send_bytes_with_length(sock2,Nonce_SesKVeh)
        print("LE SELF PORT IS: "+str(self.session_number))
        print("LE SELF PORTCAR IS: "+str(port_car)) ##replace self.session_number by self.port is port is not NATED.
        dict[self.int_session_number]["BD_uc_uo"] = self.BD_uc_uo
        dict[self.int_session_number]["ID_AT"] = self.ID_AT
        dict[self.int_session_number]["ID_BD"] = self.ID_BD
        dict[self.int_session_number]["start_time_A1"] = self.start_time_A1

        return self.BD_uc_uo,Sigma_AT_SUB_REQ,C_AT,Nonce_SesKVeh,self.ID_BD,dict
 

    def step_A4(self):
        global dict
        'RECEIVE FROM THE CAR'
        num_session = receiveint(self)
        #self.send_text2("\nSession Number received")
        print('NUM SESSION IS: '+str(num_session))
        self.BD_uc_uo=dict[num_session]["BD_uc_uo"]
        self.ID_AT=dict[num_session]["ID_AT"]
        self.ID_BD=dict[num_session]["ID_BD"]
        self.start_time_A1=dict[num_session]["start_time_A1"]
        Sigma_AT_SUB_ACK = receive_bytes_with_length(self)
        dict[num_session]["Sigma_AT_SUB_ACK"]=Sigma_AT_SUB_ACK
        h_BD_uc_uo = receive_bytes_with_length(self)
        print("\nh_BD_uc_uo Received : "+h_BD_uc_uo.decode())
        dict[num_session]["h_BD_uc_uo"]=h_BD_uc_uo
        h_BD_uc_uo_prime=hashlib.sha256((self.BD_uc_uo.encode())).hexdigest()
        if h_BD_uc_uo_prime==h_BD_uc_uo.decode():
            print("h_BD_uc_uo CHECKED AND OK")
        else:
            print("h_BD_uc_uo FAIL VERIFICATION")
        certificate_car=get_certificate("cert_car.crt")
        Sigma_AT_SUB_ACK_data=self.ID_BD+self.ID_AT+h_BD_uc_uo.decode()
        print("IDS ARE :"+"ID BD "+self.ID_BD+" ID_AT "+self.ID_AT)
        print("Sigma_AT_SUB_ACK_data: "+Sigma_AT_SUB_ACK_data)
        res=verifsign(certificate_car,Sigma_AT_SUB_ACK,Sigma_AT_SUB_ACK_data.encode())
        print("Sigma_AT_SUB_ACK Verified Successfully")
        print("\n\n--- time of Step A1 to A4 ---: %s" % (time.time() - self.start_time_A1))
        dict[num_session]["TIME"] = time.time() - self.start_time_A1

        with open('file_time.csv', mode='a', newline='') as fichier_csv:
            writer = csv.writer(fichier_csv)
            writer.writerow([num_session,time.time() - self.start_time_A1])
        print("END OF STEP 1/3")
        
        
        
        #CONNECTION WITH THE PORTABLE AGAIN
    def updated_step(self):
                
        ## Receiving Session Number (for threading)
        num_session=receiveint(self)
        print("num session is: "+str(num_session))
        Sigma_AT_SUB_ACK=dict[num_session]["Sigma_AT_SUB_ACK"]
        h_BD_uc_uo=dict[num_session]["h_BD_uc_uo"]
        ID_BD=dict[num_session]["ID_BD"]
        ID_AT=dict[num_session]["ID_AT"]

        ## Sending Sigma_AT_SUB_ACK
        send_bytes_with_length(self.clientsocket,Sigma_AT_SUB_ACK) #Envoi de la signature en Byte
        ## Sending h_BD_uc_uo
        send_bytes_with_length(self.clientsocket,h_BD_uc_uo)
        #Envoi de la signature en Byte
        ID_BD_ID_AT=str(ID_BD)+"\n"+str(ID_AT)
        send_bytes_with_length(self.clientsocket,ID_BD_ID_AT.encode()) #Envoi de la signature en Byte
        print("all files sent")
        Activity_phase2=receive_bytes_with_length(self)
        print("Activity_time is: "+str(Activity_phase2))
        with open('file_time2.csv', mode='a', newline='') as fichier_csv:
            writer = csv.writer(fichier_csv)
            writer.writerow([num_session,Activity_phase2])
        print("END OF STEP 2/3")




    def run(self):
        
        print("Thread",threading.get_ident(),"started")
        step=receivestring(self)
        print(step)
        if step=="reservation":
            self.reservation()
        elif step=="step_A4":
            self.step_A4()
        elif step=="updated_step":
            self.updated_step()



private_key_sp,public_key, private_key_sp_pem=generate_keys() #Generation of the keys
private_key_car,public_key, private_key_car_pem=generate_keys_car() #Generation of the keys
print("Keys generated ready") #SEVER IS NOW READY
server(HOST,PORTS)
