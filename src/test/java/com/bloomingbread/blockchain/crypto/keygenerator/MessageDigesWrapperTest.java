package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.blockchain.crypto.CryptoByteUtils;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class MessageDigesWrapperTest {
    @Test
    public void digestWithDefalut() throws Exception {
        System.out.println(MessageDigesWrapper.DEFAULT_ALGORITHM);
        MessageDigesWrapper digestUtils = new MessageDigesWrapper();
        String message1 = CryptoByteUtils.randomString(56);
        byte[] digest1 = digestUtils.digest(message1.getBytes("UTF-8"));

        String message2 = CryptoByteUtils.randomString(1) + message1.substring(1) ;
        byte[] digest2 = digestUtils.digest(message2.getBytes("UTF-8"));

        assertEquals(digest1, digest2);
    }

    @Test
    public void digestWithMD5() throws Exception {
        String digestAlgorithm = "MD5";
        System.out.println(digestAlgorithm);
        MessageDigesWrapper digestUtils = new MessageDigesWrapper();
        String message1 = CryptoByteUtils.randomString(56);
        byte[] digest1 = digestUtils.digest(message1.getBytes("UTF-8"), digestAlgorithm);

        String message2 = CryptoByteUtils.randomString(1) + message1.substring(1) ;
        byte[] digest2 = digestUtils.digest(message2.getBytes("UTF-8"), digestAlgorithm);

        assertEquals(digest1, digest2);
    }

    @Test
    public void digestWithSha256() throws Exception {
        String digestAlgorithm1 = "SHA-1";
        String digestAlgorithm2 = "SHA-256";
        MessageDigesWrapper digestUtils = new MessageDigesWrapper();
        String message1 = CryptoByteUtils.randomString(56);
        byte[] digest1 = digestUtils.digest(message1.getBytes("UTF-8"), digestAlgorithm1);

        String message2 = CryptoByteUtils.randomString(1) + message1.substring(1) ;
        byte[] digest2 = digestUtils.digest(message2.getBytes("UTF-8"), digestAlgorithm2);

        assertNotEquals(message1, message2);
    }
    @Test
    public void findMessageDigestAlgorithm() throws Exception {
        String digestAlgorithm = "SHA-256";
        MessageDigesWrapper digestUtils = new MessageDigesWrapper();
        String message1 = CryptoByteUtils.randomString(56);
        byte[] digest1 = digestUtils.digest(message1.getBytes("UTF-8"), digestAlgorithm);
        assertEquals(digestAlgorithm, digestUtils.findMessageDigestAlgorithm(message1.getBytes("UTF-8"), digest1));
    }
}