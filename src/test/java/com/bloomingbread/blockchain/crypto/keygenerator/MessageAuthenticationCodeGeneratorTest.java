package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.blockchain.crypto.CryptoByteUtils;
import com.bloomingbread.crypto.JCEProviderInfo;
import com.bloomingbread.crypto.MessageAuthenticationCodeGenerator;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

public class MessageAuthenticationCodeGeneratorTest {
/*    @Test
    public void getAuthenticationCode() throws Exception {
        MessageAuthenticationCodeGenerator macWrapper = new MessageAuthenticationCodeGenerator();
        KeyGeneratorWrapper keyGeneratorWrapper = new KeyGeneratorWrapper();

        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();

        List<String> macAlgorithms = jceProviderInfo.getAvailableAlgorithm(macWrapper.providerName, MessageAuthenticationCodeGenerator.SERVICE);
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

    @Test
    public void toStringTest() {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();
        List<String> providers = jceProviderInfo.getAvailableProviders();
        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, MessageAuthenticationCodeGenerator.SERVICE)) {
                List<String> algorithms = jceProviderInfo.getAvailableAlgorithm(provider, MessageAuthenticationCodeGenerator.SERVICE);
                Collections.sort(algorithms);
                System.out.println(String.format("- %s", provider));
                System.out.println(String.format("%s", Arrays.toString(algorithms.toArray())));
            }
        });
    }*/
}