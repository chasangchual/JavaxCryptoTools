package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.blockchain.crypto.CryptoByteUtils;
import com.bloomingbread.crypto.AsymmetricKeyPairGenerator;
import com.bloomingbread.crypto.DigitalSignatureUtils;
import com.bloomingbread.crypto.JCEProviderInfo;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class DigitalSignatureUtilsTest {
/*
    @Test
    public void veriySignature() throws UnsupportedEncodingException {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();

        Map<String, Map<String, List<String>>> result = new ConcurrentHashMap<>();

        byte[] messsage = CryptoByteUtils.randomString(56).getBytes("UTF-8");

        List<String> providers = jceProviderInfo.getAvailableProviders();

        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, DigitalSignatureUtils.SERVICE)
                    && jceProviderInfo.isAvailableService(provider, AsymmetricKeyPairGenerator.SERVICE)) {

                result.put(provider, new ConcurrentHashMap<>());

                List<String> digitalSignatureAlgorithms = jceProviderInfo.getAvailableAlgorithm(provider, DigitalSignatureUtils.SERVICE);
                List<String> keypairGeneratorAlgorithms = jceProviderInfo.getAvailableAlgorithm(provider, AsymmetricKeyPairGenerator.SERVICE);

                DigitalSignatureUtils digitalSignatureUtils = new DigitalSignatureUtils(provider, digitalSignatureAlgorithms.get(0));
                AsymmetricKeyPairGenerator asymmetricKeyPairGenerator = new AsymmetricKeyPairGenerator(provider, keypairGeneratorAlgorithms.get(0));

                digitalSignatureAlgorithms.forEach(digitalSignatureAlgorithm -> {
                    result.get(provider).put(digitalSignatureAlgorithm, new Vector<>());
                    keypairGeneratorAlgorithms.forEach(keyGeneratorAlgorithm -> {
                        try {
                            KeyPair key = asymmetricKeyPairGenerator.newKeyPair(keyGeneratorAlgorithm);

                            byte[] signature = digitalSignatureUtils.generateSignature(messsage, digitalSignatureAlgorithm, key.getPrivate());
                            boolean verifiedResult = digitalSignatureUtils.veriySignature(messsage, signature, digitalSignatureAlgorithm, key.getPublic());

                            if(verifiedResult) {
                                result.get(provider).get(digitalSignatureAlgorithm).add(keyGeneratorAlgorithm);
                            }
                        } catch (Exception e) {
                            // ignore in case it failed to decode
                        }
                    });
                });
            }
        });

        ResultPrintUtil.print(result);
    }

    @Test
    public void toStringTest() {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();
        List<String> providers = jceProviderInfo.getAvailableProviders();
        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, DigitalSignatureUtils.SERVICE)) {
                List<String> algorithms = jceProviderInfo.getAvailableAlgorithm(provider, DigitalSignatureUtils.SERVICE);
                Collections.sort(algorithms);
                System.out.println(String.format("- %s", provider));
                System.out.println(String.format("%s", Arrays.toString(algorithms.toArray())));
            }
        });
    }*/
}