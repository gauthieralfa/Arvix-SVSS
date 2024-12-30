package com.example.svss_app;
import android.os.Build;
import androidx.annotation.RequiresApi;
import android.util.Log;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class phase1serverActivity implements Runnable {
    long startactivity;
    String BD_uo_uc;
    String ServerAdress;
    Socket socket;
    DataOutputStream out;
    int port;

    public phase1serverActivity(String s, String BD_uo_uc, long startactivity,int port) throws IOException {
        this.ServerAdress = s;
        this.BD_uo_uc = BD_uo_uc;
        this.startactivity=startactivity;
        this.port=port;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void OpenClientCommunication() throws IOException {
        try {
            System.out.println("Connection in process...");
            Log.v("TEST", "Communication started !");
            try {
                socket = new Socket(this.ServerAdress, port);
            } catch (IOException e) {
                e.printStackTrace();
            }
            Log.v("TEST", "Communication OK !");
        } catch (Exception e) {
            e.printStackTrace();
        }

        //Sending Session Number to the SP
        out = new DataOutputStream(socket.getOutputStream()); //Output Stream socket
        out.writeUTF("reservation");
        System.out.println("---RESERVATION STEP---"+port);
        out.flush();

        out.writeUTF(String.valueOf(socket.getLocalPort())); //Sending Session Number to the SP (for threading management)
        out.flush();
        System.out.println(port+"Session Number SENT:\n" + socket.getLocalPort());

        //Sending Booking Details BD_uo_uc
        out.writeUTF(BD_uo_uc);
        out.flush();
        System.out.println(port+"BD_uc_uo SENT:\n" + BD_uo_uc);
        System.out.println(port+"----- BD_uc_uo SENT to the Service Provider ----");

        // Getting time value of this step... (More relevant on the SP side)
        long endTime = System.currentTimeMillis();
        long timeActivity=endTime - startactivity;
        System.out.println("\n+"+port+"Total execution time OPEN CAR ACTIVITY: " + timeActivity);
        Variables.num_session= socket.getLocalPort(); //Updating the number session used
        System.out.println("\n+"+"Session Number used is: " + Variables.num_session); //Verifying if it is updated
        System.out.println("\n+"+"END of STEP 1/3");
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
}