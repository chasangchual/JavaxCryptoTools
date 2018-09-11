package com.bloomingbread.blockchain.myblockchain;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtils {
    public static String SHA_HASH = "SHA-256";
    private static int HEADER_VERSION = 12;

    public static String getSha256HashString(final String seed) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hash = getSha256Hash(seed);
        return getHexString(hash);
    }

    public static byte[] getSha256Hash(final String seed) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_HASH);
            byte[] hash1 = digest.digest(seed.getBytes("UTF-8"));
            byte[] hash2 = digest.digest(hash1);
            // byte[] hash2 = hash1;
            return hash2;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(); // TO-DO log exception messages
            throw e;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace(); // TO-DO log exception messages
            throw e;
        }
    }

    public static String getHexString(final byte[] bytes)  {
        StringBuffer sb = new StringBuffer();
        for(byte h : bytes) {
            sb.append(String.format("%02X", 0xff & h));
        }
        return sb.toString();
    }

    public static int getHeaderVersion() {
        return HEADER_VERSION;
    }
}
