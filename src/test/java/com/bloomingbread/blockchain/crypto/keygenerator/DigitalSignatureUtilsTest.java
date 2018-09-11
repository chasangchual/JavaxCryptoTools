package com.bloomingbread.blockchain.crypto.keygenerator;

import org.junit.Test;
import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;

import static org.junit.Assert.*;
import com.bloomingbread.blockchain.crypto.*;

public class DigitalSignatureUtilsTest {
    @Test
    public void generateMessageSignature() throws Exception {
//        DigitalSignatureUtils signatureUtils = new DigitalSignatureUtils();
//        SymmetricKeyGenerator keyGenerator = new SymmetricKeyGenerator();
//
//        SecretKey key = keyGenerator.newKey();
//        String message = CryptoByteUtils.randomString(60);
//        byte[] signature1 = signatureUtils.generateMessageSignature(message.getBytes("UTF-8"), key);
//        byte[] signature2 = signatureUtils.generateMessageSignature(message.getBytes("UTF-8"), key);
//        System.out.println(CryptoByteUtils.bytesToHexString(signature1));
//        assertArrayEquals(signature1, signature2);
   }

    @Test
    public void veriyMessageSignature() throws Exception {

    }

    @Test
    public void generateSignature() throws Exception {
//        JCEProviderInfo providerInfo = JCEProviderInfo.instance();
//        Map<String, Map<String, List<String>>> algorithmPairs = new HashMap<>();
//
//        for(String provider : providerInfo.getAvailableProviders()) {
//            if(!algorithmPairs.containsKey(provider)) {
//                algorithmPairs.put(provider, new HashMap<>());
//            }
//
//            if(providerInfo.isAvailableService(provider, DigitalSignatureUtils.SIGNATURE_SEVICE) &&
//                    providerInfo.isAvailableService(provider, AsymmetricKeyGenerator.KEYPAIR_GENERATOR_SEVICE)) {
//
//                DigitalSignatureUtils signatureUtils = new DigitalSignatureUtils(provider);
//                AsymmetricKeyGenerator keyGenerator = new AsymmetricKeyGenerator(provider);
//
//                List<String> keyGeneratorAlgorithms = providerInfo.getAvailableAlgorithm(signatureUtils.getProviderName(),
//                        AsymmetricKeyGenerator.KEY_GENERATOR_SEVICE);
//
//                List<String> cipherAlgorithms = providerInfo.getAvailableAlgorithm(signatureUtils.getProviderName(),
//                        MessageCipher.SERVICE);
//
//                byte[] message = CryptoByteUtils.randomString(60).getBytes("UTF-8");
//                SecretKey key = null;
//                byte[] signature = null;
//                for(String keyAlgorithm : keyGeneratorAlgorithms) {
//                    for(String cipherAlgorithm : cipherAlgorithms) {
//                        try {
//                            key = keyGenerator.newKey(keyAlgorithm);
//                            signature = signatureUtils.generateMessageSignature(message, key, cipherAlgorithm);
//                            signatureUtils.veriyMessageSignature(message, signature, key, cipherAlgorithm);
//                            if(!algorithmPairs.get(provider).containsKey(keyAlgorithm)) {
//                                algorithmPairs.get(provider).put(keyAlgorithm, new ArrayList());
//                            }
//
//                            algorithmPairs.get(provider).get(keyAlgorithm).add(cipherAlgorithm);
////                    System.out.println(String.format("%s - %s", keyAlgorithm, cipherAlgorithm));
//                        } catch (Exception e) {
//                        }
//                    }
//                }
//            }
//        }
//
//        for(Map.Entry<String, Map<String,List<String>>> providerEntry : algorithmPairs.entrySet()) {
//            if(providerEntry.getValue().size() > 1) {
//                System.out.println("Provider: " + providerEntry.getKey());
//                for(Map.Entry<String, List<String>> entry : providerEntry.getValue().entrySet()) {
//                    System.out.println("key algorithm: " + entry.getKey());
//                    System.out.println(Arrays.toString(entry.getValue().toArray()));
//                }
//            }
//        }
    }

    @Test
    public void generateSignature1() throws Exception {
    }

    @Test
    public void veriySignature() throws Exception {
    }

    @Test
    public void veriySignature1() throws Exception {
    }

    @Test
    public void toStringTest() throws Exception {
        DigitalSignatureUtils digitalSignatureUtils = new DigitalSignatureUtils();
        String info = digitalSignatureUtils.toString();
        System.out.println(info);
        assertNotNull(info);
    }
}