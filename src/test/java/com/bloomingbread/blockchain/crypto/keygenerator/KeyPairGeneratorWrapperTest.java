package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.crypto.JCEProviderInfo;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class KeyPairGeneratorWrapperTest {
    @Test
    public void toStringTest() {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();
        List<String> providers = jceProviderInfo.getAvailableProviders();
        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider,  KeyPairGeneratorWrapper.SERVICE)) {
                List<String> algorithms = jceProviderInfo.getAvailableAlgorithm(provider,  KeyPairGeneratorWrapper.SERVICE);
                Collections.sort(algorithms);
                System.out.println(String.format("- %s", provider));
                System.out.println(String.format("%s", Arrays.toString(algorithms.toArray())));
            }
        });
    }
}