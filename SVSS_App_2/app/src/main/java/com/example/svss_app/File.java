package com.example.svss_app;

import android.os.Environment;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;

public class File {

    public static void write_file(String data,String name) {
        FileOutputStream output = null;
        java.io.File path = new java.io.File(Environment.getExternalStorageDirectory() + "/");

        //compteur=sharedPref.getInt("valeur",0);

        java.io.File fichier = new java.io.File(path, name +".txt");
        if (fichier.isFile()) {
            fichier.delete();
            Log.v("lol", "ancien fichier de config supprimé");
        }
        //File fichierRecu = new File(path,"music"+compteur+".mp3");
        try {
            try (PrintWriter p = new PrintWriter(new FileOutputStream(fichier, true))) {
                p.print(data);
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

    public static String readFromFile(String name)
            throws IOException {
        java.io.File path = new java.io.File(Environment.getExternalStorageDirectory() + "/");
        java.io.File file = new java.io.File(path, name +".txt");
        StringBuilder resultStringBuilder = new StringBuilder();

        try (BufferedReader br
                     = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                resultStringBuilder.append(line).append("\n");
            }
        }
        return resultStringBuilder.toString();
    }
    public static void write_file_time(long data,String timeActivity) {
        FileOutputStream output = null;
        //File chemin = this.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
        java.io.File path = new java.io.File(Environment.getExternalStorageDirectory() + "/");
        int compteur = 0;

        //compteur=sharedPref.getInt("valeur",0);

        java.io.File fichier = new java.io.File(path, timeActivity + ".txt");
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
}
