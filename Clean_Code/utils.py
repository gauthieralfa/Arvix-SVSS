
import rsa
from OpenSSL import crypto,SSL

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

def receivestring(self):
    length_byte=self.clientsocket.recv(2)
    length = int.from_bytes(length_byte, byteorder='big')
    data = bytearray()
    while len(data) < length:
        packet = self.clientsocket.recv(length - len(data))
        data.extend(packet)
    string_value=data.decode('utf-8')
    return string_value

def receiveint(self):
    data=self.clientsocket.recv(4)
    print("size entier"+str(len(data)))
    int_value = int.from_bytes(data, byteorder='big')
    return int_value

def sendstring(sock,string):
    utf8_bytes = string.encode('utf-8')
    length = len(utf8_bytes)
    length_bytes = length.to_bytes(2, byteorder='big')
    sock.sendall(length_bytes + utf8_bytes)

def send_bytes_with_length(sock, byte_data):
    length = len(byte_data)
    length_bytes = length.to_bytes(4, byteorder='big')
    sock.sendall(length_bytes + byte_data)


def receive_bytes_with_length(self):
    length_bytes = self.clientsocket.recv(4)
    length = int.from_bytes(length_bytes, byteorder='big')
    data = bytearray()
    while len(data) < length:
        packet = self.clientsocket.recv(length - len(data))
        data.extend(packet)
    return bytes(data)  # Convertir en objet bytes si nécessaire