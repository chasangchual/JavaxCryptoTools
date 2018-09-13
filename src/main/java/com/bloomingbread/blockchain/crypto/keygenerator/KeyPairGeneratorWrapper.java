package com.bloomingbread.blockchain.crypto.keygenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Available algorithm in Bouncy Castle
 * DSA, DH, EC, ECMQV, ECDSA, ECDH, ECDHWITHSHA1KDF, ECDHC, ECIES, RSA, GOST3410, ECGOST3410,
 * ECGOST3410-2012, ELGAMAL, DSTU4145
 */
public class KeyPairGeneratorWrapper extends CryptoBase {
    public static final String SERVICE = "KeyPairGenerator";
    public static final String DEFAULT_ALGORITHM = "EC";

    public KeyPairGeneratorWrapper() {
        this(BouncyCastleProvider.PROVIDER_NAME, DEFAULT_ALGORITHM);
    }

    public KeyPairGeneratorWrapper(final String providerName, final String initialAlgorithm) {
        super(providerName, SERVICE, initialAlgorithm);
    }

    public KeyPair newKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        return newKeyPair(recentAlgorithm);
    }

    public KeyPair newKeyPair(final String algorithm) throws NoSuchProviderException, NoSuchAlgorithmException {
        updateRecentlyUsedAlgorithm(algorithm);

        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, this.providerName);
        return generator.generateKeyPair();
    }
}
