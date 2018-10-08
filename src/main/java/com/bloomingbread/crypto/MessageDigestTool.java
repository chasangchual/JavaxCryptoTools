package com.bloomingbread.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.List;

/**
 * Message hash generator.
 *
 * Sangchual Cha (sangchual.cha@gmail.com)
 */
public class MessageDigestTool extends CryptoBase {
    public static String SERVICE = "MessageDigest";
    public static String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    /**
     * specify message digest provider
     * @param providerName JCE provider name
     */
    public MessageDigestTool(final String providerName) {
        super(providerName, SERVICE);
    }

    public MessageDigestTool() {
        super(BouncyCastleProvider.PROVIDER_NAME, SERVICE);
    }

    /**
     * generate message hash.
     * @param message target message
     * @param algorithm algorithm to be applied. toString() shows available algorithms.
     * @return generated hash in byte[]
     * @throws NoSuchAlgorithmException invalid algorithm
     * @throws NoSuchProviderException invalid jce implementation provider
     */
    public static byte[] digest(final byte[] message, final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return digest(PROVIDER, message, algorithm);
    }

    /**
     * generate message hash.
     * @param provider jce implementation provider
     * @param message target message
     * @param algorithm algorithm to be applied. toString() shows available algorithms.
     * @return generated hash in byte[]
     * @throws NoSuchAlgorithmException invalid algorithm
     * @throws NoSuchProviderException invalid jce implementation provider
     */
    public static byte[] digest(final String provider, final byte[] message, final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return MessageDigest.getInstance(algorithm, provider).digest(message);
    }

    /**
     * generate message hash.
     * @param file target file
     * @param algorithm algorithm to be applied. toString() shows available algorithms.
     * @return generated hash in byte[]
     * @throws NoSuchAlgorithmException
     */
    public static byte[] digest(final File file, final String algorithm)
            throws NoSuchAlgorithmException, FileNotFoundException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        try {
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
            int readByte = 0;
            while( (readByte = bis.read()) != -1) {
                md.update((byte)readByte);
            }
            bis.close();
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }

        return md.digest();
    }

    /**
     * find hash algorithm with the message and the digest. try possible digest algorithm and find matching algorithm.
     * @param message target message
     * @param messageDigest digest message to search
     * @return algorithm name.
     * @throws NoSuchAlgorithmException failed to search matching hash algorithm
     * @throws NoSuchProviderException invalid jce implementation provider
     */
    public static String findMessageDigestAlgorithm(final byte[] message, final byte[] messageDigest)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        boolean found = false;
        String algorithm = "digest algorithm not found";
        JCEProviderInfo providerInfo = JCEProviderInfo.instance();

        List<String> providers = providerInfo.getAvailableProviders();

        for(int i = 0 ; !found && i < providers.size(); i++) {
            if(JCEProviderInfo.instance().isAvailableService(providers.get(i), SERVICE)) {
                List<String> algorithms = providerInfo.getAvailableAlgorithm(providers.get(i), SERVICE);
                for(int k = 0; !found && k < algorithms.size(); k++) {
                    if(Arrays.equals(messageDigest, digest(message, algorithms.get(k)))) {
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
