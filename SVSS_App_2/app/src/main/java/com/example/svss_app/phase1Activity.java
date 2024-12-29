package com.example.svss_app;


import android.annotation.SuppressLint;
import android.os.Build;
import android.provider.Settings;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import java.io.IOException;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.crypto.tink.tinkkey.KeyHandle;


public class phase1Activity extends AppCompatActivity {

    private Button mValidParametersBtn;
    private TextView ID_BD_text;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_phase1);
        final String androidId = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);

        Crypto crypto=new Crypto();
        mValidParametersBtn = (Button) findViewById(R.id.activity_parameters_valid_btn);




        int ID_BD = (int)Math.floor(Math.random() * (10000 - 1 + 1) + 1); //Random ID
        int ID_uo = (int)Math.floor(Math.random() * (10000 - 1 + 1) + 1); //Random ID
        int ID_uc = Variables.ID_uc; //Known by Customer - Fixed
        int ID_veh = (int)Math.floor(Math.random() * (10000 - 1 + 1) + 1); //Random ID

        TextView ID_BD_text= (TextView) findViewById(R.id.text_view_ID_BD);
        TextView ID_Uo_text= (TextView) findViewById(R.id.text_view_ID_Uo);
        TextView ID_uc_text= (TextView) findViewById(R.id.text_view_ID_uc);
        TextView ID_veh_text= (TextView) findViewById(R.id.text_view_ID_veh);
        ID_BD_text.setText(String.valueOf(ID_BD));
        ID_Uo_text.setText(String.valueOf(ID_uo));
        ID_uc_text.setText(String.valueOf(ID_uc));
        ID_veh_text.setText(String.valueOf(ID_veh));

        mValidParametersBtn.setOnClickListener(new View.OnClickListener() {
                                                   @RequiresApi(api = Build.VERSION_CODES.KITKAT)
                                                   @Override
                                                   public void onClick(View v) {


//Our secret message

                                                       for (int i=0;i<Variables.iteration;i++) {
                                                           long startActivity = System.currentTimeMillis();

                                                           StringBuilder hCert_uc_hex;
                                                           String hCert_uc64="";
                                                           try {
                                                               PublicKey pub_key=crypto.get_public_key("cert_customer");
                                                               MessageDigest digest = MessageDigest.getInstance("SHA-256");
                                                               byte[] hCert_uc = digest.digest(pub_key.getEncoded());

                                                               hCert_uc_hex = new StringBuilder();
                                                               for (byte b : hCert_uc) {
                                                                   hCert_uc_hex.append(String.format("%02x", b));
                                                               }

                                                               hCert_uc64= Base64.getEncoder().encodeToString(hCert_uc);
                                                               System.out.println("hCert_uc is: "+hCert_uc_hex.toString());
                                                           } catch (Exception e) {
                                                               throw new RuntimeException(e);
                                                           }

                                                           int ID_Cert_veh = (int)Math.floor(Math.random() * (10000 - 1 + 1) + 1); //Random ID
                                                           // TO DELETE : String TS_BReq = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
                                                           String BD_uo_uc = ID_BD + "\n" +ID_uo + "\n" +ID_uc + "\n" + ID_veh + "\n" + hCert_uc_hex.toString() + "\n"+ ID_Cert_veh + "\n";



                                                           phase1serverActivity client = null;
                                                           try {
                                                               client = new phase1serverActivity(Variables.address, BD_uo_uc, startActivity,Variables.port);
                                                           } catch (IOException e) {
                                                               e.printStackTrace();
                                                           }
                                                           new Thread(client).start();
                                                           //finish(); //Finish waits normally the end of the Thread to continue. Should not be used.
                                                           long endTime = System.currentTimeMillis();
                                                           long timeActivity=endTime - startActivity;
                                                           //System.out.println("\nEnd of the 10 times execution" + timeActivity);
                                                           //timeActivity_table[i]= (int) timeActivity; //THE USE OF A GLOBAL IS MANDATORY FOR THAT, with the index put.

                                                       }
                                                   }
                                               }
        );
    }
}
