package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.blockchain.crypto.CryptoByteUtils;
import com.bloomingbread.crypto.JCEProviderInfo;
import com.bloomingbread.crypto.TextSignatureUtils;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TextSignatureUtilsTest {
/*    @Test
    public void generateMessageSignature() throws Exception {
    }

    @Test
    public void veriyMessageSignature() throws Exception {
    }

    @Test
    public void findMatchingAlgorithm() throws Exception {
        JCEProviderInfo providerInfo = JCEProviderInfo.instance();
        Map<String, Map<String, Map<String, List<String>>>> algorithmPairs = new HashMap<>();

        for(String provider : providerInfo.getAvailableProviders()) {
            if(!algorithmPairs.containsKey(provider)) {
                algorithmPairs.put(provider, new HashMap<>());
            }

            if(providerInfo.isAvailableService(provider, TextSignatureUtils.SEVICE) &&
                    providerInfo.isAvailableService(provider, MessageCipherWrapper.SERVICE) &&
                    providerInfo.isAvailableService(provider, KeyGeneratorWrapper.SERVICE)) {

                List<String> keyGeneratorAlgorithms = providerInfo.getAvailableAlgorithm(provider,
                        KeyGeneratorWrapper.SERVICE);

                List<String> cipherAlgorithms = providerInfo.getAvailableAlgorithm(provider,
                        MessageCipherWrapper.SERVICE);

                List<String> signatureAlgorithms = providerInfo.getAvailableAlgorithm(provider,
                        TextSignatureUtils.SEVICE);

                TextSignatureUtils signatureUtils = new TextSignatureUtils(provider, signatureAlgorithms.get(0));
                KeyGeneratorWrapper keyGenerator = new KeyGeneratorWrapper(provider, keyGeneratorAlgorithms.get(0));

                byte[] message = CryptoByteUtils.randomString(60).getBytes("UTF-8");
                SecretKey key = null;
                byte[] signature = null;
                for(String keyAlgorithm : keyGeneratorAlgorithms) {
                    if(!algorithmPairs.get(provider).containsKey(keyAlgorithm)) {
                        algorithmPairs.get(provider).put(keyAlgorithm, new HashMap<>());
                    }
                    for(String cipherAlgorithm : cipherAlgorithms) {
                        if(!algorithmPairs.get(provider).get(keyAlgorithm).containsKey(cipherAlgorithm)) {
                            algorithmPairs.get(provider).get(keyAlgorithm).put(cipherAlgorithm, new ArrayList<>());
                        }
                        for(String signatureAlgorithm : signatureAlgorithms) {
                            try {
                                key = keyGenerator.newKey(keyAlgorithm);
                                signature = signatureUtils.generateMessageSignature(message, key, signatureAlgorithm, cipherAlgorithm);
                                signatureUtils.veriyMessageSignature(message, signature, key, signatureAlgorithm, cipherAlgorithm);
                                algorithmPairs.get(provider).get(keyAlgorithm).get(cipherAlgorithm).add(cipherAlgorithm);
                            } catch (Exception e) {
                            }
                        }
                    }
                }
            }
        }

        for(Map.Entry<String, Map<String, Map<String, List<String>>>> providerEntry : algorithmPairs.entrySet()) {
            if(providerEntry.getValue().size() > 1) {
                System.out.println("Provider: " + providerEntry.getKey());
                for(Map.Entry<String, Map<String, List<String>>> keyAlgorithmEntry : providerEntry.getValue().entrySet()) {
                    if(keyAlgorithmEntry.getValue().size() > 1) {
                        System.out.println("Symentic Key : " + providerEntry.getKey());
                        for(Map.Entry<String, List<String>> entry : keyAlgorithmEntry.getValue().entrySet()) {
                            System.out.println("Cipher: " + entry.getKey());
                            System.out.println("Digest: " + Arrays.toString(entry.getValue().toArray()));
                        }
                    }
                }
            }
        }
    }

    private boolean isValidCombition(String provide, String symenticKeyAlgorithm, String signatureAlgorithm, String cipherAlgorithm) {
        return false;
    }*/

}