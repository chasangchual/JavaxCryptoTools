package com.bloomingbread.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class TextSignatureUtils {
/*
    public byte[] generateMessageSignature(final byte[] message, final SecretKey key, final String digestAlgorithm,
                                           final String cipherAlgorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        byte[] digest = MessageDigestTool.digest(message, digestAlgorithm);

        MessageDigestTool cipher = new MessageDigestTool();
        MessageCipherTool.digest()
        byte[] cipherText = MessageDigestTool.encrypt(digest, key, cipherAlgorithm);

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
*/
}