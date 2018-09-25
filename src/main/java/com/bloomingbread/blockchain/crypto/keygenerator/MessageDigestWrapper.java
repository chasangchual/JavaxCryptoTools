package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.crypto.JCEProviderInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 *
 * Message digest API wrapper class.
 *
 * Available Message Digest Algorithm in BC
 *
 * GOST3411, GOST3411-2012-256, GOST3411-2012-512, KECCAK-224, KECCAK-288, KECCAK-256, KECCAK-384, KECCAK-512,
 * MD2, MD4, MD5, SHA-1, RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320, SHA-224, SHA-256, SHA-384, SHA-512,
 * SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512,
 * Skein-256-128, Skein-256-160, Skein-256-224, Skein-256-256, Skein-512-128, Skein-512-160, Skein-512-224,
 * Skein-512-256, Skein-512-384, Skein-512-512, Skein-1024-384, Skein-1024-512, Skein-1024-1024, SM3, TIGER,
 * WHIRLPOOL, BLAKE2B-512, BLAKE2B-384, BLAKE2B-256, BLAKE2B-160, BLAKE2S-256, BLAKE2S-224, BLAKE2S-160,
 * BLAKE2S-128, DSTU7564-256, DSTU7564-384, DSTU7564-512
 *
 * by Sangchual Cha (sangchual.cha@gmail.com)
 *
 */
public class MessageDigestWrapper extends CryptoBase {
    public static final String SERVICE = "MessageDigest";
    public static final String DEFAULT_ALGORITHM = "SHA-512";

    public MessageDigestWrapper() {
        this(BouncyCastleProvider.PROVIDER_NAME, DEFAULT_ALGORITHM);
    }

    public MessageDigestWrapper(final String providerName, final String initialAlgorithm) {
        super(providerName, SERVICE, initialAlgorithm);
    }

    /**
     * create message digest with recently used algorithm
     *
     * @param message target message in byte[]
     * @return message digest
     * @throws NoSuchAlgorithmException recentAlgorithm is not supported by the provider
     */
    public byte[] digest(final byte[] message) throws NoSuchAlgorithmException {
        return digest(message, recentAlgorithm);
    }

    public byte[] digest(final byte[] message, final String algorithm) throws NoSuchAlgorithmException {
        updateRecentlyUsedAlgorithm(algorithm);
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(message);
        return messageDigest.digest();
    }

    public String findMessageDigestAlgorithm(final byte[] message, final byte[] messageDigest) throws NoSuchAlgorithmException {
        boolean found = false;
        String algorithm = "not found";

        List<String> providers = JCEProviderInfo.instance().getAvailableProviders();

        for(int i = 0 ; !found && i < providers.size(); i++) {
            if(JCEProviderInfo.instance().isAvailableService(providers.get(i), SERVICE)) {
                List<String> algorithms = JCEProviderInfo.instance().getAvailableAlgorithm(providers.get(i), SERVICE);
                for(int k = 0; !found && k < algorithms.size(); k++) {
                    if(Arrays.equals(messageDigest, digest(message, algorithms.get(k)))) {
                        found = true;
                        algorithm = algorithms.get(k);
                    }
                }
            }
        }

        return algorithm;
    }
}
