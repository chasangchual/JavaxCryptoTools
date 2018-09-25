package com.bloomingbread.blockchain.crypto.keygenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.jca.GetInstance;

import javax.crypto.KeyGenerator;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * KeyGenerator wrapper class.
 *
 * by Sangchual Cha (sangchual.cha@gmail.com)
 */
public class KeyGeneratorWrapper extends CryptoBase {
    public static final String SERVICE = "KeyGenerator";
    public static final String DEFAULT_ALGORITHM = "AES";

    public KeyGeneratorWrapper() {
        this(BouncyCastleProvider.PROVIDER_NAME, DEFAULT_ALGORITHM);
    }

    public KeyGeneratorWrapper(final String providerName, final String initialAlgorithm) {
        super(providerName, SERVICE, initialAlgorithm);
    }

    public SecretKey newKey() throws NoSuchAlgorithmException {
        return newKey(recentAlgorithm);
    }

    public SecretKey newKey(final String algorithm) throws NoSuchAlgorithmException {
        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength(algorithm);
        AlgorithmParameterSpec parameterSpec = javax.crypto.Cipher.getMaxAllowedParameterSpec(algorithm);

        updateRecentlyUsedAlgorithm(algorithm);
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init((int) (Math.log(maxKeySize) / Math.log(2)));
        SecretKey key = keyGen.generateKey();
        keyGen.init(new SecureRandom());
        return key ;
    }
}
