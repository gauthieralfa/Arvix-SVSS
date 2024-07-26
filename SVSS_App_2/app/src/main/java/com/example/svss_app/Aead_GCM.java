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
public class Aead_GCM {
    private final SecureRandom secureRandom = new SecureRandom();
    private final static int GCM_IV_LENGTH = 12;



    public String aead_enc(String SKey,String data_auth,String message) throws Exception {

        byte[] key = new byte[0];
        byte[] associatedData = new byte[0];
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            key = Base64.getDecoder().decode(SKey);
            associatedData = data_auth.getBytes(StandardCharsets.UTF_8);
        }
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        String ciphertext64=null;
        byte[] cipherText = encrypt(message, secretKey, associatedData);
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            ciphertext64 = Base64.getEncoder().encodeToString(cipherText);
        }
    return ciphertext64;
    }

    public String aead_dec(String SKey,String data_auth,byte[] ciphertext) throws Exception {

        //KEY to Encrypt
        byte[] key = new byte[0];
        byte[] associatedData = new byte[0];
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            key = Base64.getDecoder().decode(SKey);
            associatedData = data_auth.getBytes(StandardCharsets.UTF_8);
        }
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        //byte[] ciphertext=null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            //ciphertext = Base64.getDecoder().decode(message2);
        }
        String res=decrypt(ciphertext,secretKey,associatedData);
        return res;
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
            gcmIv = new GCMParameterSpec(128, cipherMessage, 0, GCM_IV_LENGTH);
            //String iv64="iHGkeFru6J4UkCzy";
            //byte[] iv= new byte[0];
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                //iv = Base64.getDecoder().decode(iv64);
            }
            //gcmIv = new GCMParameterSpec(128, iv);
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