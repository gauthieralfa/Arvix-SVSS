package com.example.svss_app;

import android.os.AsyncTask;
import android.os.Build;
import android.provider.Settings;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import java.io.IOException;

public class OpenActivity extends AppCompatActivity {


    private Button mValidParametersBtn;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_open_car);
        final String androidId = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);

        mValidParametersBtn = (Button) findViewById(R.id.activity_parameters_valid_btn);




        mValidParametersBtn.setOnClickListener(new View.OnClickListener() {
                                                   @RequiresApi(api = Build.VERSION_CODES.KITKAT)
                                                   @Override
                                                   public void onClick(View v) {
                                                       for (int i=0;i<Variables.iteration;i++) {
                                                           OpenCar client = null;
                                                           int ID_uc=i;
                                                           long startActivity = System.currentTimeMillis();
                                                           try {
                                                               client = new OpenCar(Variables.addresscar,ID_uc,startActivity);
                                                           } catch (IOException e) {
                                                               e.printStackTrace();
                                                           }
                                                           client.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
                                                           finish();
                                                       }


                                                   }
                                               }
        );
    }
}
