package com.bloomingbread.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

public class MessageDigestUtils {
    private static String MESSAGE_DIGEST = "MessageDigest";
    public static String findMessageDigestAlgorithm(final byte[] message, final byte[] messageDigest) throws NoSuchAlgorithmException {
        boolean found = false;
        String algorithm = "digest algorithm not found";
        JCEProviderInfo providerInfo = JCEProviderInfo.instance();

        List<String> providers = providerInfo.getAvailableProviders();

        for(int i = 0 ; !found && i < providers.size(); i++) {
            if(JCEProviderInfo.instance().isAvailableService(providers.get(i), MESSAGE_DIGEST)) {
                List<String> algorithms = providerInfo.getAvailableAlgorithm(providers.get(i), MESSAGE_DIGEST);
                for(int k = 0; !found && k < algorithms.size(); k++) {
                    if(Arrays.equals(messageDigest, MessageCrypto.digest(message, algorithms.get(k)))) {
                        found = true;
                        algorithm = algorithms.get(k);
                    }
                }
            }
        }
        if(found) {
            return algorithm;
        } else {
            throw new RuntimeException("digest algorithm not found");
        }
    }
}
