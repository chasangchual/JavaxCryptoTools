package com.bloomingbread.crypto;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * KeyGenerator helper class
 */
public class SecretKeyGenerator extends CryptoBase {
    public static final String SERVICE = "KeyGenerator";

    public SecretKeyGenerator(final String providerName) {
        super(providerName, SERVICE);
    }

    public SecretKeyGenerator() {
        super(BouncyCastleProvider.PROVIDER_NAME, SERVICE);
    }

    /**
     * create a new SecreteKey
     * @param algorithm algorithm to be used
     * @param keySize key size.
     *                https://docs.oracle.com/javase/10/docs/specs/security/standard-names.html
     *                https://www.bouncycastle.org/specifications.html
     * @return generated SecreteKey
     * @throws NoSuchAlgorithmException
     */
    public SecretKey newKey(final String algorithm, final int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        SecretKey key = keyGen.generateKey();
        keyGen.init(keySize, secureRandom);
        return key ;
    }
}