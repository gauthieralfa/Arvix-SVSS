package com.example.svss_app;

import android.os.Environment;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.util.Random;

public class Functions {
    public static String receive_base64_python(InputStream sin, DataInputStream in, PrintWriter out){
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

    public static int rand(){
        Random r = new Random();
        int low = 1;
        int high = 1000;
        int result = r.nextInt(high-low) + low;
        return result;
    }


}
