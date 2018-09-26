package com.bloomingbread.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

public class MessageDigestUtils extends CryptoBase {
    public static String SERVICE = "MessageDigest";

    public MessageDigestUtils(final String providerName) {
        super(providerName, SERVICE);
    }

    public MessageDigestUtils() {
        super(BouncyCastleProvider.PROVIDER_NAME, SERVICE);
    }

    public static byte[] digest(final byte[] message, final String algorithm) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm).digest(message);
    }

    public static String findMessageDigestAlgorithm(final byte[] message, final byte[] messageDigest) throws NoSuchAlgorithmException {
        boolean found = false;
        String algorithm = "digest algorithm not found";
        JCEProviderInfo providerInfo = JCEProviderInfo.instance();

        List<String> providers = providerInfo.getAvailableProviders();

        for(int i = 0 ; !found && i < providers.size(); i++) {
            if(JCEProviderInfo.instance().isAvailableService(providers.get(i), SERVICE)) {
                List<String> algorithms = providerInfo.getAvailableAlgorithm(providers.get(i), SERVICE);
                for(int k = 0; !found && k < algorithms.size(); k++) {
                    if(Arrays.equals(messageDigest, MessageCipher.digest(message, algorithms.get(k)))) {
                        found = true;
                        algorithm = algorithms.get(k);
                    }
                }
            }
        }

        if(found) {
            return algorithm;
        } else {
            throw new NoSuchAlgorithmException("digest algorithm not found");
        }
    }
}
