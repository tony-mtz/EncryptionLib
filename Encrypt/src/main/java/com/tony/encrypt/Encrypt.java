package com.tony.encrypt;

/**
 * Anthony Martinez
 * Class Encrypt: has two methods Enc and Dec

 */

import org.bouncycastle.jce.provider.*;
import org.bouncycastle.util.encoders.Hex;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.Files;
import com.google.gson.*;
import java.io.File;


public class Encrypt {

    //Will use BouncyCastle as the provider
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public String Enc(String test){
        /*create IV
          1-Create random
          2-Create a byte[] of the size of the IV
          3-Get next random
          4-Create the IV by passing in your byte[] into IvParameterSpec
        */
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        byte[] aesPlusIV;
        String aesIVString="";
        String rsaK="";
        String hmacHex="";
        
        /**
         * uncomment if you are not sure what size you are currently
         * limited to.  You may need to download the Java Cryptography Extension:
         * http://www.oracle.com/technetwork/java/javase/downloads/index.html
         * 
        try {
            System.out.println(Cipher.getMaxAllowedKeyLength("AES"));
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Error: " + ex.getMessage());
        }

        **/
        try {

            /*
             "BC" : bouncy castle
             Generate an AES key with size of 256.
             Create a cipher using AES/CBC/PKCS7Padding.
             Set cipher to ENCRYPT_MODE and pass in key, and IV.
            */
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
            keyGen.init(256);//256);
            SecretKey aesKey = keyGen.generateKey();
            Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            encrypt.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            //encrypt text and pass to byte[]
            byte [] aesCipher = encrypt.doFinal(test.getBytes());
            //stream to concat iv and aesCipher
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();
            outStream.write(iv.getIV());
            outStream.write(aesCipher);
            outStream.close();
            //convert to send in json
            aesPlusIV = outStream.toByteArray();
            aesIVString = Hex.toHexString(aesPlusIV);

            /* Test decrypt
            byte[] t = Arrays.copyOfRange(aesPlusIV, 16, aesPlusIV.length);
            //test decrypt
            Cipher dec = Cipher.getInstance("AES/CBC/PKCS7Padding", "SC");
            dec.init(Cipher.DECRYPT_MODE, aesKey, iv);
            byte[] decMsg =dec.doFinal(t);
            System.out.println("this is my msg: " + new String(decMsg));
            */

            /*Hmac
              1-Generate a Hmac key with SHA256
              2-Generate Hmac and init with SHA256 key created
              3-hmac.doFinal on concat iv+aes
             */
            //1
            KeyGenerator hmacKeyGenerator = KeyGenerator.getInstance("HMacSHA256", "BC");
            hmacKeyGenerator.init(256);
            SecretKey hKey = hmacKeyGenerator.generateKey();
            // 2- hmac
            Mac hmac = Mac.getInstance("HMacSHA256", "BC");
            hmac.init(hKey);
            //3
            byte[] hmacDat = hmac.doFinal(aesPlusIV);
            hmacHex = Hex.toHexString(hmacDat);
            System.out.println("Enc hmac : "+ hmacHex);

            /*RSA
              Get public key from directory
              Parse pem
              Get pem bytes
              Convert bytes to X509EncodedKeySpec
              Get cipher with RSA/NONE/OAEPPadding
              Encrypt, pass in a generated key from KeyFactory
             */

           //https://stackoverflow.com/questions/24137463/how-to-load-public-certificate-from-pem-file/24139603

            String keyPath = "G:/_git/EncryptionLib/Encrypt/pubkey.pem"; //get pem            
            byte[] ff = Files.readAllBytes(new File(keyPath).toPath());
            
            X509EncodedKeySpec x509 = new X509EncodedKeySpec(ff);//pubkey); //encode
            KeyFactory keyGenRSA = KeyFactory.getInstance("RSA", "BC"); //sets to rsa key
            
            
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding", "BC");
            c.init(Cipher.ENCRYPT_MODE, keyGenRSA.generatePublic(x509));

            //concatenate aes key and hmac key
            outStream = new ByteArrayOutputStream();
            outStream.write(aesKey.getEncoded());
            outStream.write(hKey.getEncoded());
            outStream.close();
            //encrypt concatenated keys
            byte[] rsaC = c.doFinal(outStream.toByteArray());
            rsaK = Hex.toHexString(rsaC); //get hex string
            

        } catch (InvalidKeyException e) {
            System.out.println("invalide key " + e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("invalide key 1 " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.out.println("invalide key 2" + e.getMessage());
        } catch (FileNotFoundException e) {
            System.out.println("invalide key 3" + e.getMessage());
        } catch (NoSuchProviderException e) {
            System.out.println("invalide key 4" + e.getMessage());
        } catch (InvalidKeySpecException e) {
            System.out.println("invalide key 5" + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            System.out.println("invalide key 6" + e.getMessage());
        } catch (BadPaddingException e) {
            System.out.println("invalide key 7" + e.getMessage());
        } catch (NoSuchPaddingException e) {
            System.out.println("invalide key 8" + e.getMessage());
        } catch (IOException e) {
            e.printStackTrace();
        } 

        /*Keys is a POJO, Gson is a json library
          Using Gson to convert Keys into json
         */
        Keys gsonK = new Keys(aesIVString, hmacHex, rsaK);
        Gson gson = new Gson();
        return gson.toJson(gsonK, Keys.class);
    }

    /**
     *
     * @param jObj is a json object that is retrieved with Gson
     */
    public String Dec(String jObj)  {

        String message="";//message to return
        Gson gson = new Gson();
        Keys data = gson.fromJson(jObj, Keys.class);       
        try {
            /*retrieve json from jObj
             1-Read in private key
             2-Create cipher to decrypt
             3-Decrypt
             4-Separate aes and hmac keys
             */
            //1-            
            String keyPathP = "G:/_git/EncryptionLib/Encrypt/privkey.pem"; //get pem            
            byte[] ff = Files.readAllBytes(new File(keyPathP).toPath());
            PKCS8EncodedKeySpec pkcs = new PKCS8EncodedKeySpec(ff); //encode
            KeyFactory rsaKey = KeyFactory.getInstance("RSA","BC");
            //2- pass in recovered rsa key      
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding", "BC");
            c.init(Cipher.DECRYPT_MODE,rsaKey.generatePrivate(pkcs));
            //3 - pass in to byte array
            byte[] savedKeys = c.doFinal(Hex.decode(data.rsa));
            //4-
            byte[] aesK = Arrays.copyOfRange(savedKeys, 0, savedKeys.length/2);
            byte[] hmacK = Arrays.copyOfRange(savedKeys, savedKeys.length/2, savedKeys.length);
            /*hmac
              1-Get aes and iv in aes
              2-create hmac
              3-retrieve hmac key
              4-encrypt ivaes
             */
            //-1
            byte[] aesIv = Hex.decode(data.ivaes);
            //2-
            Mac hmac = Mac.getInstance("HMacSHA256", "BC");
            //3
            SecretKey hKey = new SecretKeySpec(hmacK, 0, hmacK.length, "HMacSHA256");
            hmac.init(hKey);
            //4
            byte[] hmacDat = hmac.doFinal(aesIv);
            String hmacHexString = Hex.toHexString(hmacDat);

            System.out.println("Old hmac: " + data.hmac);
            System.out.println("New hmac: " + hmacHexString);
            System.out.println("RSA : " + data.rsa);
            //check if hmac sent in and hmac recreated match
            //if they match proceed, else do nothing
            if(data.hmac.equalsIgnoreCase(hmacHexString)){
                //split to iv and cipher
                //decode aes with this iv and cipher to decode
                byte[] ivBytes = Arrays.copyOfRange(aesIv, 0, 16);
                byte[] msg = Arrays.copyOfRange(aesIv,16, aesIv.length);

                KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
                keyGen.init(256);
                SecretKey k = new SecretKeySpec(aesK,0,aesK.length,"AES");
                //SecretKey k = keyGen.getAlgorithm("AES");
                Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                encrypt.init(Cipher.DECRYPT_MODE, k, iv);
                byte[] wow= encrypt.doFinal(msg, 0, msg.length);
                message = new String(wow);
                //System.out.println("WTF.............." + new String(wow));

            }else{
                System.out.println("DID NOT MATCH!!");
            }


        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            //e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            //e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } 

        return message;
    }
}
