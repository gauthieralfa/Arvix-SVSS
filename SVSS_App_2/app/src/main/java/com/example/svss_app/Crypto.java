package com.example.svss_app;

import android.os.Build;
import androidx.annotation.RequiresApi;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import static java.nio.charset.StandardCharsets.UTF_8;

// Create a Main class
public class Crypto {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }


        @RequiresApi(api = Build.VERSION_CODES.O)
        public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
            byte[] bytes = Base64.getDecoder().decode(cipherText);

            Cipher decriptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

            return new String(decriptCipher.doFinal(bytes));
        }


    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes());
        String cipher = null;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            cipher=Base64.getEncoder().encodeToString(cipherText);
        }
        return cipher;
    }

        public static String sign(String plainText, PrivateKey privateKey) throws Exception {
            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privateKey);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                privateSignature.update(plainText.getBytes(UTF_8));
            }

            byte[] signature = privateSignature.sign();
            String signature_string=null;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                signature_string= Base64.getEncoder().encodeToString(signature);
            }
            return signature_string;
        }

        public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKey);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                publicSignature.update(plainText.getBytes(UTF_8));
            }

            byte[] signatureBytes = new byte[0];
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                signatureBytes = Base64.getDecoder().decode(signature);
            }

            return publicSignature.verify(signatureBytes);
        }

        public static String pbkdf2(char[] Key_char,byte[] value,int iterations) {
            PBEKeySpec spec = new PBEKeySpec(Key_char, value, iterations, 64 * 4);
            byte[] key_gen=null;
            String key_gen64=null;
            try {
                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                key_gen = skf.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                key_gen64 = Base64.getEncoder().encodeToString(key_gen);
            }
            return key_gen64;
        }

        public static String MAC(String key64,byte[] message){
                String mac_res=null;
                byte[] decodedmasterKey = new byte[0];
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    decodedmasterKey = Base64.getDecoder().decode(key64);
                }

                //SecretKey masterkey = new SecretKeySpec(decodedmasterKey, 0, decodedmasterKey.length, "AES");
                System.out.println("Taille: " +decodedmasterKey.length);
                try {
                    mac_res=calcHmacSha256(decodedmasterKey,message);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                System.out.println("CheckUo: "+mac_res);
                return mac_res;

        }

        static public String calcHmacSha256(byte[] secretKey, byte[] message)throws Exception {
                byte[] hmacSha256 = null;
                Mac mac = Mac.getInstance("HmacSHA256");
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
                mac.init(secretKeySpec);
                String res=null;
                hmacSha256 = mac.doFinal(message);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    return res=Base64.getEncoder()
                            .encodeToString(hmacSha256);
                }
                return res;
            }



        @RequiresApi(api = Build.VERSION_CODES.O)
        public PublicKey get_public_key(String namekey)
                throws Exception {

            byte[] keyBytes = Files.readAllBytes(Paths.get("/storage/emulated/0/"+namekey+".der"));


            X509EncodedKeySpec spec =
                    new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }




        public static PrivateKey get_private_key(String namekey)
                throws Exception {

            byte[] keyBytes = new byte[0];
            keyBytes = Files.readAllBytes(Paths.get("/storage/emulated/0/" + namekey + ".der"));

            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }



        @RequiresApi(api = Build.VERSION_CODES.KITKAT)
        public static String encrypt_aes(String algorithm, String input, SecretKey key,
                                         IvParameterSpec iv) throws Exception{

            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] cipherText = cipher.doFinal(input.getBytes());
            String res = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                return res=Base64.getEncoder()
                        .encodeToString(cipherText);
            }
            return res;
        }

        @RequiresApi(api = Build.VERSION_CODES.KITKAT)
        public static String encrypt_aes_ecb(String algorithm, String input, SecretKey key,
                                             IvParameterSpec iv) throws Exception{

            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = cipher.doFinal(input.getBytes());
            System.out.println("O_check byte "+cipherText);
            String res = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                return res=Base64.getEncoder()
                        .encodeToString(cipherText);
            }
            return res;
        }


    }
