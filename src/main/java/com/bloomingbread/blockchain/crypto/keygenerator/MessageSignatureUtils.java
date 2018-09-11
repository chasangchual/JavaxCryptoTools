package com.bloomingbread.blockchain.crypto.keygenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class MessageSignatureUtils extends CryptoBase {
    public static final String SEVICE = MessageDigesWrapper.SEVICE;
    public static final String DEFAULT_ALGORITHM = MessageDigesWrapper.DEFAULT_ALGORITHM;

    public MessageSignatureUtils() {
        this(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME);
    }

    public MessageSignatureUtils(final String providerName) {
        super(providerName, SEVICE, DEFAULT_ALGORITHM);
    }

    public byte[] generateMessageSignature(final byte[] message, final Key key, final String digestAlgorithm,
                                           final String cipherAlgorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        MessageDigesWrapper digestUtils = new MessageDigesWrapper();
        byte[] digest = digestUtils.digest(message, digestAlgorithm);

        MessageCipher cipher = new MessageCipher();
        byte[] cipherText = cipher.encrypt(digest, key, cipherAlgorithm);

        return cipherText;
    }

    public boolean veriyMessageSignature(final byte[] message, final byte[] signature, final Key key,
                                         final String digestAlgorithm, final String cipherAlgorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        MessageDigesWrapper digestUtils = new MessageDigesWrapper();
        byte[] digest = digestUtils.digest(message, digestAlgorithm);

        MessageCipher cipher = new MessageCipher();
        byte[] cipherText = cipher.decrypt(digest, key, cipherAlgorithm);

        return Arrays.equals(signature, cipherText);
    }
}