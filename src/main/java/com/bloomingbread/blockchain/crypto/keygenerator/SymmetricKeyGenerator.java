package com.bloomingbread.blockchain.crypto.keygenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class SymmetricKeyGenerator extends CryptoBase {
    public static final String SEVICE = "KeyGenerator";
    public static final String DEFAULT_ALGORITHM = "AES";

    public SymmetricKeyGenerator() {
        this(BouncyCastleProvider.PROVIDER_NAME);
    }

    public SymmetricKeyGenerator(final String providerName) {
        super(providerName, SEVICE, DEFAULT_ALGORITHM);
    }

    public SecretKey newKey() throws NoSuchAlgorithmException {
        return newKey(DEFAULT_ALGORITHM);
    }

    public SecretKey newKey(final String algorithm) throws NoSuchAlgorithmException {
        updateRecentlyUsedAlgorithm(algorithm);
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        return keyGen.generateKey();
    }
}
