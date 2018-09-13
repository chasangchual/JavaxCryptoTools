package com.bloomingbread.blockchain.crypto.keygenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class MessageSignatureUtils extends CryptoBase {
    public static final String SEVICE = MessageDigestWrapper.SERVICE;
    public static final String DEFAULT_ALGORITHM = MessageDigestWrapper.DEFAULT_ALGORITHM;

    public MessageSignatureUtils() {
        this(BouncyCastleProvider.PROVIDER_NAME, DEFAULT_ALGORITHM);
    }

    public MessageSignatureUtils(final String providerName, final String initialAlgorithm) {
        super(providerName, SEVICE, initialAlgorithm);
    }

    public byte[] generateMessageSignature(final byte[] message, final SecretKey key, final String digestAlgorithm,
                                           final String cipherAlgorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        MessageDigestWrapper digestUtils = new MessageDigestWrapper();
        byte[] digest = digestUtils.digest(message, digestAlgorithm);

        MessageCipherWrapper cipher = new MessageCipherWrapper();
        byte[] cipherText = cipher.encrypt(digest, key, cipherAlgorithm);

        return cipherText;
    }

    public boolean veriyMessageSignature(final byte[] message, final byte[] signature, final SecretKey key,
                                         final String digestAlgorithm, final String cipherAlgorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        MessageDigestWrapper digestUtils = new MessageDigestWrapper();
        byte[] digest = digestUtils.digest(message, digestAlgorithm);

        MessageCipherWrapper cipher = new MessageCipherWrapper();
        byte[] cipherText = cipher.decrypt(digest, key, cipherAlgorithm);

        return Arrays.equals(signature, cipherText);
    }
}