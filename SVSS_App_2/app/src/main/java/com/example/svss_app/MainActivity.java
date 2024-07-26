package com.example.svss_app;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;


public class MainActivity extends AppCompatActivity {

    private Button phase_open;
    private Button phase1;
    private Button phase2;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ActivityCompat.requestPermissions(this, permissions, REQUEST_DATA_PERMISSION);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        phase1 = (Button) findViewById(R.id.activity_main_phase1_btn);
        phase2 = (Button) findViewById(R.id.activity_main_phase2_btn);
        phase_open = (Button) findViewById(R.id.activity_main_open_btn);

        phase1.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent phase1Activity = new Intent(MainActivity.this, com.example.svss_app.phase1Activity.class);
                startActivity(phase1Activity);
            }
        });

        phase2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent phase2Activity = new Intent(MainActivity.this, com.example.svss_app.phase2Activity.class);
                startActivity(phase2Activity);
            }
        });


        phase_open.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent openActivity = new Intent(MainActivity.this, OpenActivity.class);
                startActivity(openActivity);
            }
        });




    }


    // PERMISSIONS OF THE APP
    private static final int REQUEST_DATA_PERMISSION = 200;
    private boolean permissionToRecordAccepted = false;
    private String [] permissions = {Manifest.permission.READ_EXTERNAL_STORAGE,Manifest.permission.WRITE_EXTERNAL_STORAGE};



    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode){
            case REQUEST_DATA_PERMISSION:
                permissionToRecordAccepted  = grantResults[0] == PackageManager.PERMISSION_GRANTED;
                break;
        }
        if (!permissionToRecordAccepted ) finish();

    }


}
