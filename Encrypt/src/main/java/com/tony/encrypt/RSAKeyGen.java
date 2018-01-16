package com.tony.encrypt;
import org.bouncycastle.jce.provider.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.RSAKeyGenParameterSpec;

public class RSAKeyGen {

    private static final int KEY_SIZE = 2048;

    //Will use BouncyCastle as the provider
    //"BC" will not be recognized without this
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair generate() {
        try {
            SecureRandom random = new SecureRandom();
            RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(KEY_SIZE, RSAKeyGenParameterSpec.F4);
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            generator.initialize(spec, random);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

