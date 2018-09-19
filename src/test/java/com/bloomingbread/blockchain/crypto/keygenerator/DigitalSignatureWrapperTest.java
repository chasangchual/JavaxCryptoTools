package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.blockchain.crypto.CryptoByteUtils;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.*;

public class DigitalSignatureWrapperTest {

    @Test
    public void veriySignature() throws UnsupportedEncodingException {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();

        Map<String, Map<String, List<String>>> result = new ConcurrentHashMap<>();

        byte[] messsage = CryptoByteUtils.randomString(56).getBytes("UTF-8");

        List<String> providers = jceProviderInfo.getAvailableProviders();

        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, DigitalSignatureWrapper.SERVICE)
                    && jceProviderInfo.isAvailableService(provider, KeyPairGeneratorWrapper.SERVICE)) {

                result.put(provider, new ConcurrentHashMap<>());

                List<String> digitalSignatureAlgorithms = jceProviderInfo.getAvailableAlgorithm(provider, DigitalSignatureWrapper.SERVICE);
                List<String> keypairGeneratorAlgorithms = jceProviderInfo.getAvailableAlgorithm(provider, KeyPairGeneratorWrapper.SERVICE);

                DigitalSignatureWrapper digitalSignatureWrapper = new DigitalSignatureWrapper(provider, digitalSignatureAlgorithms.get(0));
                KeyPairGeneratorWrapper keyPairGeneratorWrapper = new KeyPairGeneratorWrapper(provider, keypairGeneratorAlgorithms.get(0));

                digitalSignatureAlgorithms.forEach(digitalSignatureAlgorithm -> {
                    result.get(provider).put(digitalSignatureAlgorithm, new Vector<>());
                    keypairGeneratorAlgorithms.forEach(keyGeneratorAlgorithm -> {
                        try {
                            KeyPair key = keyPairGeneratorWrapper.newKeyPair(keyGeneratorAlgorithm);

                            byte[] signature = digitalSignatureWrapper.generateSignature(messsage, digitalSignatureAlgorithm, key.getPrivate());
                            boolean verifiedResult = digitalSignatureWrapper.veriySignature(messsage, signature, digitalSignatureAlgorithm, key.getPublic());

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
            if(jceProviderInfo.isAvailableService(provider, DigitalSignatureWrapper.SERVICE)) {
                List<String> algorithms = jceProviderInfo.getAvailableAlgorithm(provider, DigitalSignatureWrapper.SERVICE);
                Collections.sort(algorithms);
                System.out.println(String.format("- %s", provider));
                System.out.println(String.format("%s", Arrays.toString(algorithms.toArray())));
            }
        });
    }
}