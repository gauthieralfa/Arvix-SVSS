package com.example.svss_app;

import android.os.AsyncTask;
import android.os.Build;
import androidx.annotation.RequiresApi;
import android.util.Log;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.Socket;

import java.security.PrivateKey;
import java.security.PublicKey;


import static java.nio.charset.StandardCharsets.UTF_8;

public class OpenCar extends AsyncTask<Void, Void, Void> {
    String ServerAdress;
    Socket socket;
    PrintWriter out;
    int ID_uc;
    long startActivity;
    DataOutputStream out2;
    DataInputStream in2;

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

        //NEW CODE

        out2 = new DataOutputStream(socket.getOutputStream()); //Output Stream socket
        in2 = new DataInputStream((socket.getInputStream())); //Input Stream socket
        out2.writeUTF("open");
        out2.flush();

        int challenge_uc = (int)Math.floor(Math.random() * (1000000000 - 1 + 1) + 1);
        String challenge_uc_string=String.valueOf(challenge_uc);
        String ID_UC=String.valueOf(Variables.ID_uc);

        PrivateKey pri_key = null;
        PublicKey pub_key=null;
        String Sigma_CR_AC_REQ=null;
        try {
            pri_key = Crypto.get_private_key("priv_customer");
            pub_key=crypto.get_public_key("pub_customer");
            Sigma_CR_AC_REQ = Crypto.sign(challenge_uc_string+"\n"+ID_UC+"\n"+Variables.h_BD_uc_uo64, pri_key);
        } catch (Exception e) {
            e.printStackTrace();
        }
        out2.writeUTF(Sigma_CR_AC_REQ);
        System.out.println("Signature Sigma_CR_AC_REQ sent to the car: "+Sigma_CR_AC_REQ);
        out2.flush();

        out2.writeUTF(challenge_uc_string);
        System.out.println("challenge_uc sent to the car:"+challenge_uc_string);
        out2.flush();

        out2.writeUTF(ID_UC);
        System.out.println("ID_UC sent to the car:"+ID_UC);
        out2.flush();

        // TO MODIFY -> hash Contract BD and not hash BD UC UO !!!
        out2.writeUTF(Variables.h_BD_uc_uo64);
        System.out.println("h_BD_uc_uo sent to the car:"+Variables.h_BD_uc_uo64);
        out2.flush();

        String pub_key_str=String.valueOf(pub_key);
        byte[] pub_key_bytes = pub_key.getEncoded();
        out2.write(pub_key_bytes);
        System.out.println("pub_key sent to the car: "+pub_key_bytes);
        out2.flush();

        //END NEW CODE


/*
        out=new PrintWriter(socket.getOutputStream());//Gestion du flux sortant
        out.print("open");
        System.out.println("open sent");
        out.flush();

        DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
*/

        //int challenge_uc = (int)Math.floor(Math.random() * (1000000000 - 1 + 1) + 1);
        //String challenge_uc_string=String.valueOf(challenge_uc);
        //String ID_UC="12";
        /*PrivateKey pri_key = null;
        PublicKey pub_key=null;
        String Sigma_CR_AC_REQ=null;
        try {
            pri_key = Crypto.get_private_key("priv_customer");
            pub_key=crypto.get_public_key("pub_customer");
            Sigma_CR_AC_REQ = Crypto.sign(challenge_uc_string+"\n"+ID_UC+"\n"+Variables.h_BD_uc_uo64, pri_key);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Sending Sigma_uc
        out.print(Sigma_CR_AC_REQ);
        System.out.println("Signature Sigma_Uc sent to the car: "+Sigma_CR_AC_REQ);
        out.flush();
        */
        //Sending Challenge_uc


        //String msg2=(String)in.readUTF();
        //System.out.println("Received from the server : "+msg2);
        /*challenge_uc_string=String.valueOf(challenge_uc);
        out.print(challenge_uc_string);
        System.out.println("challenge_uc sent to the car:"+challenge_uc_string);
        out.flush();
*/
        //Sending Cert_uc

        /*msg2=(String)in.readUTF();
        System.out.println("Received from the server : "+msg2);

        String pub_key_str=String.valueOf(pub_key);
        out.print(pub_key);
        System.out.println("pub_key sent to the car:"+pub_key_str);
        out.flush();

        msg2=(String)in.readUTF();
        System.out.println("Received from the server : "+msg2);

         */
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