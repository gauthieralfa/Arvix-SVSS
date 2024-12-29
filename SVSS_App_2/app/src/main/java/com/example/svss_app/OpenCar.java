package com.example.svss_app;

import android.annotation.SuppressLint;
import android.os.AsyncTask;
import android.os.Build;
import androidx.annotation.RequiresApi;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import javax.crypto.Mac;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
//import com.google.crypto.tink.tinkkey.KeyAccess;
//import com.google.crypto.tink.tinkkey.KeyHandle;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import static java.nio.charset.StandardCharsets.UTF_8;

public class OpenCar extends AsyncTask<Void, Void, Void> {
    String ServerAdress;
    Socket socket;
    PrintWriter out;
    int ID_uc;
    long startActivity;

    public OpenCar(String s,int ID_uc,long startActivity) throws IOException {
        this.ServerAdress = s;
        this.ID_uc=ID_uc;
        this.startActivity=startActivity;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void OpenClientCommunication() throws Exception {
        try {
            startActivity = System.currentTimeMillis();
            System.out.println("Vehicle Access STEP...");
            Log.v("TEST", "Communication started !");
            try {
                socket = new Socket(ServerAdress, Variables.portcar);
            } catch (IOException e) {
                e.printStackTrace();
            }
            Log.v("TEST", "Communication OK !");
            System.out.println("Connexion réussie avec le serveur");
        } catch (Exception e) {
            e.printStackTrace();
        }
        Crypto crypto=new Crypto();
        out=new PrintWriter(socket.getOutputStream());//Gestion du flux sortant
        out.print("open");
        System.out.println("open sent");
        out.flush();

        DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));


        int challenge_uc = (int)Math.floor(Math.random() * (1000000000 - 1 + 1) + 1);
        String challenge_uc_string=String.valueOf(challenge_uc);
        String ID_UC="12";
        PrivateKey pri_key = null;
        PublicKey pub_key=null;
        String Sigma_Uc=null;
        try {
            pri_key = Crypto.get_private_key("priv_customer");
            pub_key=crypto.get_public_key("pub_customer");
            Sigma_Uc = Crypto.sign(challenge_uc_string+"\n"+ID_UC, pri_key);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Sending Sigma_uc
        out.print(Sigma_Uc);
        System.out.println("Signature Sigma_Uc sent to the car: "+Sigma_Uc);
        out.flush();

        //Sending Challenge_uc
        String msg2=(String)in.readUTF();
        System.out.println("Received from the server : "+msg2);
        challenge_uc_string=String.valueOf(challenge_uc);
        out.print(challenge_uc_string);
        System.out.println("challenge_uc sent to the car:"+challenge_uc_string);
        out.flush();

        //Sending Cert_uc

        msg2=(String)in.readUTF();
        System.out.println("Received from the server : "+msg2);

        String pub_key_str=String.valueOf(pub_key);
        out.print(pub_key);
        System.out.println("pub_key sent to the car:"+pub_key_str);
        out.flush();

        msg2=(String)in.readUTF();
        System.out.println("Received from the server : "+msg2);

        long endTime = System.currentTimeMillis();
        long timeActivity=endTime - startActivity;
        System.out.println("\nTotal execution time OPEN CAR ACTIVITY: " + timeActivity);





    }


    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    public Void doInBackground(Void... arg0) {
        Log.v("TEST", "Thread Lancé !");
        try {
            OpenClientCommunication();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return null;
    }
    @Override
    public void onPostExecute(Void result) {
        super.onPostExecute(result);
    }


}