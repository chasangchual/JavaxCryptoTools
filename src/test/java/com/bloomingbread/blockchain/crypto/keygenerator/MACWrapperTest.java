package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.blockchain.crypto.CryptoByteUtils;
import org.junit.Test;

import javax.crypto.SecretKey;

/**

 */
public class MACWrapperTest {
    @Test
    public void authenticate() throws Exception {
        MACWrapper authenticationCode = new MACWrapper();
        byte[] messsage1 = CryptoByteUtils.randomString(56).getBytes("UTF-8");
        SecretKey key = authenticationCode.createKey();

        byte[] code1 = authenticationCode.getAuthenticationCode(messsage1, key);
        byte[] code2 = authenticationCode.getAuthenticationCode(messsage1, key);

        System.out.println(String.format("messge: %s\nmac1: %s", CryptoByteUtils.bytesToHexString(messsage1),
                CryptoByteUtils.bytesToHexString(code1)));
        System.out.println(String.format("messge: %s\nmac2: %s", CryptoByteUtils.bytesToHexString(messsage1),
                CryptoByteUtils.bytesToHexString(code2)));
        System.out.println(String.format("mac1: %s\nmac2: %s", CryptoByteUtils.bytesToHexString(code1),
                CryptoByteUtils.bytesToHexString(code2)));
    }
}