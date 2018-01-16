package com.tony.encrypt;

/**
 * Anthony Martinez
 */

public class Keys {
    String ivaes;
    String hmac;
    String rsa;
    Keys(String aes, String hmac, String rsa){
        this.ivaes = aes;
        this.hmac = hmac;
        this.rsa = rsa;
    }

    public String getIvaes(){return ivaes;}
    public String getHmac(){return hmac;}
    public String getRsa(){return rsa;}

}
