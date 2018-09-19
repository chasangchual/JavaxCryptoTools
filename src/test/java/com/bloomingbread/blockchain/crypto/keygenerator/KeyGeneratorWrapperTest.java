package com.bloomingbread.blockchain.crypto.keygenerator;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class KeyGeneratorWrapperTest {
    @Test
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
}