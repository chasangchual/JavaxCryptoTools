package com.bloomingbread.crypto;

import com.bloomingbread.blockchain.crypto.CryptoByteUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class MessageDigestToolTest {
    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Test
    public void digestWithMD5() throws Exception {
        MessageDigestTool messageDigestTool = new MessageDigestTool();
        String message = CryptoByteUtils.randomString(56);

        byte[] digest1 = MessageDigestTool.digest(message.getBytes("UTF-8"), "MD5");
        byte[] digest2 = MessageDigestTool.digest(message.getBytes("UTF-8"), "MD5");

        assertArrayEquals(digest1, digest2);
    }

    @Test
    public void digest_Sha256_different_message() throws Exception {
        String digestAlgorithm = "SHA-256";

        String message1 = CryptoByteUtils.randomString(56);
        byte[] digest1 = MessageDigestTool.digest(message1.getBytes("UTF-8"), digestAlgorithm);

        String message2 = CryptoByteUtils.randomString(1) + message1.substring(1) ;
        byte[] digest2 = MessageDigestTool.digest(message2.getBytes("UTF-8"), digestAlgorithm);

        assertFalse(Arrays.equals(digest1, digest2));
    }

    @Test
    public void findMessageDigestAlgorithm() throws Exception {
        String digestAlgorithm = "SHA-256";
        String message1 = CryptoByteUtils.randomString(56);
        byte[] digest1 = MessageDigestTool.digest(message1.getBytes("UTF-8"), digestAlgorithm);
        assertEquals(digestAlgorithm, MessageDigestTool.findMessageDigestAlgorithm(message1.getBytes("UTF-8"), digest1));
    }

    @Test
    public void toStringTest() {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();
        List<String> providers = jceProviderInfo.getAvailableProviders();
        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, MessageDigestTool.SERVICE)) {
                List<String> algorithms = jceProviderInfo.getAvailableAlgorithm(provider, MessageDigestTool.SERVICE);
                Collections.sort(algorithms);
                System.out.println(String.format("- %s", provider));
                System.out.println(String.format("%s", Arrays.toString(algorithms.toArray())));
            }
        });
    }

    @Test
    public void digestFileWithSha256() throws Exception {
        String digestAlgorithm = "SHA-256";
        String fileName = "test.dat";
        File file = testFolder.newFile(fileName);
        String message = CryptoByteUtils.randomString(2048 * 256);
        Files.write(Paths.get(file.toURI()), message.getBytes("UTF-8"));
        byte[] digest1 = MessageDigestTool.digest(file, digestAlgorithm);
        byte[] digest2 = MessageDigestTool.digest(message.getBytes("UTF-8"), digestAlgorithm);
        System.out.println(Base64.getEncoder().encodeToString(MessageDigestTool.digest(file, digestAlgorithm)));
        assertArrayEquals(digest1, digest2);
    }
}