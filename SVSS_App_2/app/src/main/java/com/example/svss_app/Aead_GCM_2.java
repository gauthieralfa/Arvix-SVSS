package com.example.svss_app;

import android.os.Build;



import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;


/**
 * A simple showcase for encryption and decryption with AES + GCM in Java
 */
public class Aead_GCM_2 {
    private final SecureRandom secureRandom = new SecureRandom();
    private final static int GCM_IV_LENGTH = 12;


    public String testEncryption() throws Exception {
        //create new random key
        //byte[] key = new byte[16];
        //secureRandom.nextBytes(key);
        String Kuo="HEaV63ebUEAjib07VBqK3/HRq0q/u4y1mLNULYzZgI0=";
        byte[] key = new byte[0];
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            key = Base64.getDecoder().decode(Kuo);
        }


        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] associatedData = new byte[0]; //meta data you want to verify with the secret message
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.KITKAT) {
            associatedData = "ProtocolVersion1".getBytes(StandardCharsets.UTF_8);
        }

        String message = "the secret message";

        //byte[] cipherText = encrypt(message, secretKey, associatedData);
        String ciphertext64="iHGkeFru6J4UkCzyyIkBf74C5rluCJlI3MrrWdUoaLJto+ImhJq51xoaST8c2g==";
        byte[] ciphertext= new byte[0];
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            ciphertext = Base64.getDecoder().decode(ciphertext64);
        }
        String decrypted = decrypt(ciphertext, secretKey, associatedData);


        return decrypted;
    }

    /**
     * Encrypt a plaintext with given key.
     *
     * @param plaintext      to encrypt (utf-8 encoding will be used)
     * @param secretKey      to encrypt, must be AES type, see {@link SecretKeySpec}
     * @param associatedData optional, additional (public) data to verify on decryption with GCM auth tag
     * @return encrypted message
     * @throws Exception if anything goes wrong
     */
    public byte[] encrypt(String plaintext, SecretKey secretKey, byte[] associatedData) throws Exception {

        byte[] iv = new byte[GCM_IV_LENGTH]; //NEVER REUSE THIS IV WITH SAME KEY
        secureRandom.nextBytes(iv);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            System.out.println("Voici le IV: "+Base64.getEncoder().encodeToString(iv));
        }
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = null; //128 bit auth tag length
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            parameterSpec = new GCMParameterSpec(128, iv);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            if (associatedData != null) {
                cipher.updateAAD(associatedData);
            }
        }



        byte[] cipherText = new byte[0];
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        }

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        return byteBuffer.array();
    }

    /**
     * Decrypts encrypted message (see {@link #encrypt(String, SecretKey, byte[])}).
     *
     * @param cipherMessage  iv with ciphertext
     * @param secretKey      used to decrypt
     * @param associatedData optional, additional (public) data to verify on decryption with GCM auth tag
     * @return original plaintext
     * @throws Exception if anything goes wrong
     */
    public String decrypt(byte[] cipherMessage, SecretKey secretKey, byte[] associatedData) throws Exception {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        //use first 12 bytes for iv
        GCMParameterSpec gcmIv = null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            //gcmIv = new GCMParameterSpec(128, cipherMessage, 0, GCM_IV_LENGTH);
            String iv64="iHGkeFru6J4UkCzy";
            byte[] iv= new byte[0];
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                iv = Base64.getDecoder().decode(iv64);
            }
            gcmIv = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmIv);
            if (associatedData != null) {
                cipher.updateAAD(associatedData);
            }

        }


        //use everything from 12 bytes on as ciphertext
        byte[] plainText = cipher.doFinal(cipherMessage, GCM_IV_LENGTH, cipherMessage.length - GCM_IV_LENGTH);
        String res=null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            res=new String(plainText, StandardCharsets.UTF_8);
            System.out.println("Voici le AEAD RES: "+res);
        }
        return res;
    }
}