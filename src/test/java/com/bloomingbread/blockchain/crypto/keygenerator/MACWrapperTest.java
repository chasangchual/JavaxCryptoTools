package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.blockchain.crypto.CryptoByteUtils;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.util.List;

import static org.junit.Assert.assertNotNull;

/**

 */
public class MACWrapperTest {
    @Test
    public void authenticate() throws Exception {
        MACWrapper macWrapper = new MACWrapper();
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();
        List<String> macAlgorithms = jceProviderInfo.getAvailableAlgorithm(macWrapper.providerName, MACWrapper.SERVICE);

        byte[] messsage = CryptoByteUtils.randomString(56).getBytes("UTF-8");

        for (String macAlgorithm : macAlgorithms) {
            SecretKey key = macWrapper.createKey(macAlgorithm);
            byte[] code = macWrapper.getAuthenticationCode(messsage, key);
            assertNotNull(code);
        }
    }
}