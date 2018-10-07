package com.bloomingbread.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyPairGenerator;

/**
 *
 *
 * Available algorithm in Bouncy Castle
 * DSA, DH, EC, ECMQV, ECDSA, ECDH, ECDHWITHSHA1KDF, ECDHC, ECIES, RSA, GOST3410, ECGOST3410,
 * ECGOST3410-2012, ELGAMAL, DSTU4145
 */
public class AsymmetricKeyPairGenerator extends CryptoBase {
    public static final String SERVICE = "AsymmetricKeyPairGenerator";

    public AsymmetricKeyPairGenerator(final String providerName) {
        super(providerName, SERVICE);
    }

    public AsymmetricKeyPairGenerator() {
        super(BouncyCastleProvider.PROVIDER_NAME, SERVICE);
    }

    public KeyPair newKeyPair(final String algorithm, final int keySize) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, this.providerName);
        generator.initialize(keySize, secureRandom);
        return generator.generateKeyPair();
    }
}
