package com.example.svss_app;

import android.os.Build;
import androidx.annotation.RequiresApi;
import android.util.Log;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Base64;

public class phase2serverActivity implements Runnable {

    String ServerAdress;
    Socket socket;
    DataOutputStream out;
    DataInputStream in;
    long startActivity;

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

        Crypto crypto=new Crypto(); //Loading Crypto functions
        out = new DataOutputStream(socket.getOutputStream()); //Output Stream socket
        in = new DataInputStream((socket.getInputStream())); //Input Stream socket

        //Indicating the step to the SP
        out.writeUTF("updated_step"); //going to the second step
        out.flush();
        System.out.println("updated_step sent to the SP");

        // Sending Session Number to the SP
        //out.writeInt(Variables.num_session); //Sending Session Number to the SP
        out.writeUTF(String.valueOf(Variables.ID_uc));
        out.flush();
        System.out.println("Num Session sent to the SP is: "+Variables.ID_uc);


        //Receiving Sigma_AT_SUB_ACK from the SP
        byte[] Sigma_AT_SUB_ACK=receiveByte(in);
        String Sigma_AT_SUB_ACK_str=new String(Sigma_AT_SUB_ACK);
        String Sigma_AT_SUB_ACK644 = Base64.getEncoder().encodeToString(Sigma_AT_SUB_ACK);
        System.out.println("Server received Sigma_AT_SUB_ACK: "+Sigma_AT_SUB_ACK644);

        //Receiving h_BD_uc_uo from the SP
        byte[] h_BD_uc_uo=receiveByte(in);
        String h_BD_uc_uo64=new String(h_BD_uc_uo);
        System.out.println("Server received h_BD_uc_uo: "+h_BD_uc_uo64);


        //receiving IB_BD and ID_AT from the SP
        byte[] ID_BD_ID_AT=receiveByte(in);
        String ID_BD_ID_AT_str=new String(ID_BD_ID_AT);
        System.out.println("Server received ID_BD_ID_AT_str: "+ID_BD_ID_AT_str);
        String[] lines = ID_BD_ID_AT_str.split("\n", -1);
        String ID_BD=lines[0];
        String ID_AT=lines[1];

        // Checking Signature of Sigma_AT_SUB_ACK
        PublicKey pub_key = null;
        boolean verif = Boolean.parseBoolean(null);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                pub_key=crypto.get_public_key("pub_car");
                verif=crypto.verify(ID_BD+ID_AT+h_BD_uc_uo64,Sigma_AT_SUB_ACK644,pub_key);
                if (verif==true){
                    System.out.println("Signature Sigma_AT_SUB_ACK IS OK!\n" );
                }
                else{
                    System.out.println("!!! WRONG Signature Sigma_AT_SUB_ACK !!!\n" );
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            //Receiving hashContractBD !
            byte[] hContractBD_byte=receiveByte(in);
            String hContractBD=new String(hContractBD_byte);
            Variables.hContractBD=hContractBD;
            System.out.println("Server received hContractBD: "+hContractBD);



            // Getting time value of this step...
            long endTime = System.currentTimeMillis();
            long timeActivity=endTime - startActivity;
            System.out.println("\nTotal execution time PHASE 2: " + timeActivity +" ms");
            int time_int=(int)timeActivity;
            System.out.println("\nTotal execution INT: " + time_int +" ms");
            //out.writeInt(time_int); //Sending time to the SP that will put it in a file...
            out.writeUTF(String.valueOf(time_int));
            out.flush();
            System.out.println("END OF STEP 2/3 ");
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
    public static byte[] receiveByte(DataInputStream in) throws IOException {
        int length=in.readInt();
        byte[] data=new byte[length];
        in.readFully(data);
        return data;
    }
}