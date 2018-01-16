
/**
 * @author tonyd
 */
package com.tony.encrypt;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Test {    
    public static void main(String args[]){        
        KeyPair keys = RSAKeyGen.generate();
        PublicKey pkey = keys.getPublic();
        PrivateKey privkey = keys.getPrivate();        
        try {            
            FileOutputStream keyinfo = new FileOutputStream("pubkey.pem");
            keyinfo.write(pkey.getEncoded());
            keyinfo.flush();
            keyinfo.close();         
            keyinfo = new FileOutputStream("privkey.pem");
            keyinfo.write(privkey.getEncoded());
            keyinfo.flush();
            keyinfo.close();
        } catch (Exception ex) {
            System.out.println("ERR:" + ex);
        }
        
        Encrypt enc = new Encrypt();
        String secrete = enc.Enc("Hello Jess!!");
        System.out.println(secrete);
        System.out.println("here: " + enc.Dec(secrete));              
    }    
}