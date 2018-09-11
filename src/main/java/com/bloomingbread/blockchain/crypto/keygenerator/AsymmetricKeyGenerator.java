package com.bloomingbread.blockchain.crypto.keygenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * Available algorithm in Bouncy Castle
 * DSA, DH, EC, ECMQV, ECDSA, ECDH, ECDHWITHSHA1KDF, ECDHC, ECIES, RSA, GOST3410, ECGOST3410,
 * ECGOST3410-2012, ELGAMAL, DSTU4145
 */
public class AsymmetricKeyGenerator extends CryptoBase {
    public static final String KEYPAIR_GENERATOR_SEVICE = "KeyPairGenerator";
    public static final String DEFAULT_KEYPAIR_ALGORITHM = "EC";

    public AsymmetricKeyGenerator() {
        this(BouncyCastleProvider.PROVIDER_NAME);
    }

    public AsymmetricKeyGenerator(final String providerName) {
        super(providerName, KEYPAIR_GENERATOR_SEVICE, DEFAULT_KEYPAIR_ALGORITHM);
    }

    public KeyPair newKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        return newKeyPair(DEFAULT_KEYPAIR_ALGORITHM);
    }

    public KeyPair newKeyPair(final String algorithm) throws NoSuchProviderException, NoSuchAlgorithmException {
        updateRecentlyUsedAlgorithm(algorithm);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, this.providerName);
        return generator.generateKeyPair();
    }
}
