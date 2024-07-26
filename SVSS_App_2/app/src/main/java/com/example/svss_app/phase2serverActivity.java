package com.example.svss_app;

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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

//import com.google.crypto.tink.tinkkey.KeyAccess;
//import com.google.crypto.tink.tinkkey.KeyHandle;


public class phase2serverActivity implements Runnable {

    String ServerAdress;
    Socket socket;
    PrintWriter out;
    long startActivity;
    Boolean go = false;

    public phase2serverActivity(String s,long startActivity) throws IOException {
        this.ServerAdress = s;
        this.startActivity=startActivity;
    }


    public void OpenClientCommunication() throws IOException {
        try {
            startActivity = System.currentTimeMillis();
            Log.v("TEST", "Communication started !");
            try {
                socket = new Socket(ServerAdress, Variables.port);
                System.out.println("PORT SOCKET: "+socket.getPort());
                System.out.println("LOCAL PORT SOCKET: "+socket.getLocalPort());

            } catch (IOException e) {
                e.printStackTrace();
            }
            Log.v("TEST", "Communication OK !");
            System.out.println("Connection successful with the Service Provider");
        } catch (Exception e) {
            e.printStackTrace();
        }

        Crypto crypto=new Crypto();
        DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        out=new PrintWriter(socket.getOutputStream());//Gestion du flux sortant
        out.print("updated_step");
        out.flush();
        System.out.println("updated_step_sent");

        String msg=(String)in.readUTF();
        System.out.println("Received from the server :"+msg);

        out.print("OK");
        out.flush();

        InputStream sin = socket.getInputStream();
        byte[] size_buff = new byte[4];
        sin.read(size_buff);

        int size = ByteBuffer.wrap(size_buff).asIntBuffer().get();
        System.out.println("size received: "+ size);

        out.print("OK");
        out.flush();

        byte[] Sigma_AT_SUB_ACK = new byte[0];
        if(size>0) {
            Sigma_AT_SUB_ACK = new byte[size];
            in.readFully(Sigma_AT_SUB_ACK, 0, Sigma_AT_SUB_ACK.length); // read the message
        }
        String Sigma_AT_SUB_ACK64=new String(Sigma_AT_SUB_ACK);
        System.out.println("Server received Sigma_AT_SUB_ACK: "+Sigma_AT_SUB_ACK64);


        out.print("OK");
        out.flush();


//h_BD_uc_uo Received

        sin.read(size_buff);
        size = ByteBuffer.wrap(size_buff).asIntBuffer().get();
        System.out.println("size received: "+ size);

        out.print("OK");
        out.flush();

        byte[] h_BD_uc_uo = new byte[0];
        if(size>0) {
            h_BD_uc_uo = new byte[size];
            in.readFully(h_BD_uc_uo, 0, h_BD_uc_uo.length); // read the message
        }
        String h_BD_uc_uo64=new String(h_BD_uc_uo);

        String Sigma_AT_SUB_ACK644 = Base64.getEncoder().encodeToString(Sigma_AT_SUB_ACK);
        System.out.println("Server received h_BD_uc_uo: "+h_BD_uc_uo64);


        out.print("OK");
        out.flush();


//ID_BD_ID_AT Received

        sin.read(size_buff);
        size = ByteBuffer.wrap(size_buff).asIntBuffer().get();
        System.out.println("taille reçue: "+ size);

        out.print("OK");
        out.flush();

        byte[] ID_BD_ID_AT = new byte[0];
        if(size>0) {
            ID_BD_ID_AT = new byte[size];
            in.readFully(ID_BD_ID_AT, 0, ID_BD_ID_AT.length); // read the message
        }
        String ID_BD_ID_AT_str=new String(ID_BD_ID_AT);
        System.out.println("Server received ID_BD_ID_AT_str: "+ID_BD_ID_AT_str);
        String[] lines = ID_BD_ID_AT_str.split("\n", -1);
        String ID_BD=lines[0];
        String ID_AT=lines[1];

        // CHECK Signature
        PublicKey pub_key = null;
        PrivateKey pri_key=null;
        boolean verif = Boolean.parseBoolean(null);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                pub_key=crypto.get_public_key("pub_car");
                pri_key=crypto.get_private_key("priv_customer");
                verif=crypto.verify(ID_BD+ID_AT+h_BD_uc_uo64,Sigma_AT_SUB_ACK644,pub_key);
                if (verif==true){
                    System.out.println("Signature Sigma_AT_SUB_ACK OK!\n" );
                }
                else{
                    System.out.println("!!! Signature Sigma_AT_SUB_ACK NOK !!!\n" );
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
            long endTime = System.currentTimeMillis();
            long timeActivity=endTime - startActivity;
            System.out.println("\nTotal execution time PHASE 2: " + timeActivity);
        }
    }


    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    public void run() {
        Log.v("TEST", "Thread Lancé !");
        try {
            OpenClientCommunication();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static String receive_base64_python(InputStream sin, DataInputStream in,PrintWriter out){
        byte[] size_buff = new byte[1024];
        try {
            sin.read(size_buff);
        } catch (IOException e) {
            e.printStackTrace();
        }
        int size = ByteBuffer.wrap(size_buff).asIntBuffer().get();
        System.out.format("Expecting %d bytes\n", size);


        out.print("OK");
        out.flush();

        byte[] message = new byte[0];
        if(size>0) {
            message = new byte[size];
            try {
                in.readFully(message, 0, message.length); // read the message
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        String res64=new String(message);
        return res64;
    }

}