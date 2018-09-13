package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.blockchain.crypto.CryptoByteUtils;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

public class MACWrapperTest {
    @Test
    public void getAuthenticationCode() throws Exception {
        MACWrapper macWrapper = new MACWrapper();
        KeyGeneratorWrapper keyGeneratorWrapper = new KeyGeneratorWrapper();

        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();

        List<String> macAlgorithms = jceProviderInfo.getAvailableAlgorithm(macWrapper.providerName, MACWrapper.SERVICE);
        List<String> keyAlgorithms = jceProviderInfo.getAvailableAlgorithm(macWrapper.providerName, KeyGeneratorWrapper.SERVICE);

        byte[] messsage = CryptoByteUtils.randomString(56).getBytes("UTF-8");

        for (String macAlgorithm : macAlgorithms) {
            for (String keyAlgorithm : keyAlgorithms) {
                try {
                    SecretKey key = keyGeneratorWrapper.newKey(keyAlgorithm);
                    byte[] code1 = macWrapper.getAuthenticationCode(messsage, macAlgorithm, key);
                    byte[] code2 = macWrapper.getAuthenticationCode(messsage, macAlgorithm, key);
                    assertArrayEquals(code1, code2);

                    System.out.println(String.format("mac: %s, key: %s", macAlgorithm, keyAlgorithm));
                } catch (Exception e) {

                }
            }
        }
    }
}