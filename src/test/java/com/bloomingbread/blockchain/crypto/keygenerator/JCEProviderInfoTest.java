package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.crypto.JCEProviderInfo;
import org.junit.Test;

import static org.junit.Assert.*;

// Available service in BC

// X509Store, AlgorithmParameterGenerator, SecureRandom, AsymmetricKeyPairGenerator, CertificateFactory, KeyStore, Mac,
// X509StreamParser, CertPathValidator, Signature, Cipher, CertPathBuilder, MessageDigest, KeyAgreement,
// KeyGenerator, SecretKeyFactory, CertStore, KeyFactory, AlgorithmParameters
public class JCEProviderInfoTest {
    @Test
    public void instance() throws Exception {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();
        System.out.println(jceProviderInfo.toString());
    }

    @Test
    public void getProvider() throws Exception {
    }

    @Test
    public void isProviderAvailable() throws Exception {
    }

    @Test
    public void getAvailableServices() throws Exception {
    }

    @Test
    public void getServices() throws Exception {
    }

    @Test
    public void getAvailableAlgorithm() throws Exception {
    }

    @Test
    public void isServiceAvailable() throws Exception {
    }

}