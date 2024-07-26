package com.example.svss_app;

import static androidx.core.content.ContextCompat.startActivity;

import android.content.Intent;
import android.os.Build;
import android.os.Environment;
import androidx.annotation.RequiresApi;

import android.util.Log;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PublicKey;

public class phase1serverActivity implements Runnable {
    long startactivity;
    PublicKey publicKey;
    String BD_uo_uc;
    String ServerAdress;
    String BAvail;
    Socket socket;
    BufferedReader in;
    PrintWriter out;

    public phase1serverActivity(String s, String BD_uo_uc, long startactivity) throws IOException {
        this.ServerAdress = s;
        this.BD_uo_uc = BD_uo_uc;
        this.startactivity=startactivity;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void OpenClientCommunication() throws IOException {
        try {
            System.out.println("Connection in process...");
            Log.v("TEST", "Communication started !");
            try {
                socket = new Socket(ServerAdress, Variables.port);
            } catch (IOException e) {
                e.printStackTrace();
            }
            Log.v("TEST", "Communication OK !");
        } catch (Exception e) {
            e.printStackTrace();
        }

        out = new PrintWriter(socket.getOutputStream());//Gestion du flux sortant
        out.print("reservation");
        System.out.println("---RESERVATION STEP---");
        out.flush();

        DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        String msg = (String) in.readUTF();
        System.out.println("Received from the server: " + msg);

        out.print(BD_uo_uc);
        out.flush();
        System.out.println("BD_uc_uo SENT:\n" + BD_uo_uc);

        String msg2 = (String) in.readUTF();
        System.out.println("Received from the server : " + msg2);
        System.out.println("----- BD_uc_uo SENT to the Service Provider ----");

        long endTime = System.currentTimeMillis();
        System.out.println("start time is: "+startactivity);
        System.out.println("end time is: "+endTime);

        long timeActivity=endTime - startactivity;
        System.out.println("\nTotal execution time OPEN CAR ACTIVITY: " + timeActivity);

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


    public static void write_file(long data,String timeActivity) {
        FileOutputStream output = null;
        java.io.File path = new java.io.File(Environment.getExternalStorageDirectory() + "/");
        java.io.File fichier = new File(path, timeActivity + ".txt");
        try {
            try (PrintWriter p = new PrintWriter(new FileOutputStream(fichier, true))) {
                p.println(data);
            } catch (FileNotFoundException e1) {
                e1.printStackTrace();
            }

            if (output != null)
                output.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();

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