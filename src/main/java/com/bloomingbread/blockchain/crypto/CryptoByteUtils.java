package com.bloomingbread.blockchain.crypto;

import java.security.SecureRandom;

public class CryptoByteUtils {
    private static final String RANDOM_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-";
    public static final SecureRandom random = new SecureRandom();
    public static String bytesToHexString(final byte[] bytes){
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes) {
            sb.append(String.format("%02x", b&0xff));
        }
        return sb.toString();
    }
    public static String randomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i=0; i<length; i++) {
            sb.append(RANDOM_CHARS.charAt(random.nextInt(RANDOM_CHARS.length())));
        }
        return sb.toString();
    }
}
