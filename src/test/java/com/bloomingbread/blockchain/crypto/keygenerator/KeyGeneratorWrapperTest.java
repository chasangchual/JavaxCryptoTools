package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.crypto.JCEProviderInfo;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class KeyGeneratorWrapperTest {
/*    @Test
    public void toStringTest() {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();
        List<String> providers = jceProviderInfo.getAvailableProviders();
        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, KeyGeneratorWrapper.SERVICE)) {
                List<String> algorithms = jceProviderInfo.getAvailableAlgorithm(provider, KeyGeneratorWrapper.SERVICE);
                Collections.sort(algorithms);
                System.out.println(String.format("- %s", provider));
                System.out.println(String.format("%s", Arrays.toString(algorithms.toArray())));
            }
        });
    }

    @Test
    public void newKeyForAll() {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();
        List<String> providers = jceProviderInfo.getAvailableProviders();
        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, KeyGeneratorWrapper.SERVICE)) {
                System.out.println(String.format("provider: %s", provider));

                List<String> algorithms = jceProviderInfo.getAvailableAlgorithm(provider, KeyGeneratorWrapper.SERVICE);
                algorithms.forEach(algorithm -> {
                    KeyGeneratorWrapper keyGenerator = new KeyGeneratorWrapper(provider, KeyGeneratorWrapper.DEFAULT_ALGORITHM);
                    try {
                        SecretKey key = keyGenerator.newKey(algorithm);
                        System.out.println(String.format("algorithm: %s, format: %s", key.getAlgorithm(), key.getFormat()));

                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                });
            }
        });
    }

    @Test
    public void newKey() {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();
        List<String> providers = jceProviderInfo.getAvailableProviders();
        String algorithm = "DESEDE";
        KeyGeneratorWrapper keyGenerator = new KeyGeneratorWrapper();
        try {
            SecretKey key = keyGenerator.newKey(algorithm);
            System.out.println(String.format("algorithm: %s, format: %s", key.getAlgorithm(), key.getFormat()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void CryptoPermissionCollection() {
    }*/
}