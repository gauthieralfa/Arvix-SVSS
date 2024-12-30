package com.example.svss_app;

import android.os.Build;
import android.provider.Settings;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;

import java.io.IOException;
import java.text.SimpleDateFormat;

import java.util.Random;


public class phase2Activity extends AppCompatActivity {


    private Button mValidParametersBtn;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_phase2);
        final String androidId = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);

        mValidParametersBtn = (Button) findViewById(R.id.activity_parameters_valid_btn);

        mValidParametersBtn.setOnClickListener(new View.OnClickListener() {
                                                   @RequiresApi(api = Build.VERSION_CODES.KITKAT)
                                                   @Override
                                                   public void onClick(View v) {


//Our secret message
                                                       for (int i=0;i<Variables.iteration;i++) {

                                                           String TS_Mauth = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
                                                           long startActivity = System.currentTimeMillis();
                                                           phase2serverActivity client2=null;

                                                           try {
                                                               client2 = new phase2serverActivity(Variables.address,startActivity);
                                                           } catch (IOException e) {
                                                               e.printStackTrace();
                                                           }
                                                           new Thread(client2).start();
                                                           finish();
                                                       }
                                                   }

                                               }
        );
    }
}
