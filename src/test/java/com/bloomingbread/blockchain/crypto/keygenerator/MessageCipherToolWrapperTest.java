package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.blockchain.crypto.CryptoByteUtils;
import com.bloomingbread.crypto.JCEProviderInfo;
import com.bloomingbread.crypto.AsymmetricKeyPairGenerator;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.assertArrayEquals;

/**
 * AES,
 * AESWRAP, AESWRAPPAD, AESRFC3211WRAP, AESRFC5649WRAP, CCM, GCM, PBEWITHSHAAND128BITAES-CBC-BC,
 * PBEWITHSHAAND192BITAES-CBC-BC, PBEWITHSHAAND256BITAES-CBC-BC, PBEWITHSHA256AND128BITAES-CBC-BC,
 * PBEWITHSHA256AND192BITAES-CBC-BC, PBEWITHSHA256AND256BITAES-CBC-BC, PBEWITHMD5AND128BITAES-CBC-OPENSSL,
 * PBEWITHMD5AND192BITAES-CBC-OPENSSL, PBEWITHMD5AND256BITAES-CBC-OPENSSL, ARC4, PBEWITHSHAAND128BITRC4,
 * PBEWITHSHAAND40BITRC4, ARIA,
 * ARIARFC3211WRAP, ARIAWRAP, ARIAWRAPPAD, BLOWFISH,
 * CAMELLIA,
 * CAMELLIARFC3211WRAP, CAMELLIAWRAP, CAST5,
 * CAST6, CHACHA, CHACHA7539, DES,
 * DESRFC3211WRAP,
 * PBEWITHMD2ANDDES, PBEWITHMD5ANDDES, PBEWITHSHA1ANDDES, DESEDE,
 * DESEDEWRAP,
 * DESEDERFC3211WRAP, PBEWITHSHAAND3-KEYTRIPLEDES-CBC, BROKENPBEWITHSHAAND3-KEYTRIPLEDES-CBC, OLDPBEWITHSHAAND3-KEYTRIPLEDES-CBC,
 * PBEWITHSHAAND2-KEYTRIPLEDES-CBC, BROKENPBEWITHSHAAND2-KEYTRIPLEDES-CBC, GOST28147,
 * Grainv1, Grain128, HC128, HC256, IDEA,
 * PBEWITHSHAANDIDEA-CBC, NOEKEON, RC2, RC2WRAP,
 * PBEWITHMD5ANDRC2, PBEWITHSHA1ANDRC2, PBEWITHSHAAND128BITRC2-CBC, PBEWITHSHAAND40BITRC2-CBC,
 * RC5, RC5-64, RC6, RIJNDAEL, SALSA20, SEED,
 * SEEDWRAP, Serpent, Tnepres,
 * Shacal2, SHACAL-2, SKIPJACK, SM4, TEA, Twofish, PBEWITHSHAANDTWOFISH-CBC, Threefish-256, Threefish-512, Threefish-1024,
 * VMPC, VMPC-KSA3, XTEA, XSALSA20, DSTU7624, DSTU7624-128, DSTU7624-256, DSTU7624-512,
 * DSTU7624KW, DSTU7624-128KW, DSTU7624-256KW, DSTU7624-512KW, GOST3412-2015, GOST3412-2015/CFB, GOST3412-2015/CFB8,
 * GOST3412-2015/OFB, GOST3412-2015/CBC, GOST3412-2015/CTR, IES, IESwithAES-CBC, IESWITHDESEDE-CBC, DHIES, DHIESwithAES-CBC,
 * DHIESWITHDESEDE-CBC, ECIES, ECIESwithAES-CBC, ECIESwithDESEDE-CBC, RSA, RSA/RAW, RSA/PKCS1,
 * RSA/1, RSA/2, RSA/OAEP,
 * RSA/ISO9796-1, ELGAMAL, ELGAMAL/PKCS1, BROKENPBEWITHMD5ANDDES, BROKENPBEWITHSHA1ANDDES, OLDPBEWITHSHAANDTWOFISH-CBC]
 */
public class MessageCipherToolWrapperTest {
/*
    @Test
    public void decryptSecretKey() throws Exception {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();

        Map<String, Map<String, List<String>>> result = new ConcurrentHashMap<>();

        byte[] messsage = CryptoByteUtils.randomString(56).getBytes("UTF-8");

        List<String> providers = jceProviderInfo.getAvailableProviders();

        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, MessageCipherWrapper.SERVICE) &&
                    jceProviderInfo.isAvailableService(provider, KeyGeneratorWrapper.SERVICE)) {

                result.put(provider, new ConcurrentHashMap<>());

                List<String> cipherAlgorithms = jceProviderInfo.getAvailableAlgorithm(provider, MessageCipherWrapper.SERVICE);
                List<String> keyGeneratorAlgorithms = jceProviderInfo.getAvailableAlgorithm(provider, KeyGeneratorWrapper.SERVICE);

                MessageCipherWrapper messageCipherWrapper = new MessageCipherWrapper(provider, cipherAlgorithms.get(0));
                KeyGeneratorWrapper keyGeneratorWrapper = new KeyGeneratorWrapper(provider, keyGeneratorAlgorithms.get(0));

                cipherAlgorithms.forEach(cipherAlgorithm -> {
                    result.get(provider).put(cipherAlgorithm, new Vector<>());
                    keyGeneratorAlgorithms.forEach(keyGeneratorAlgorithm -> {
                        try {
                            SecretKey key = keyGeneratorWrapper.newKey(keyGeneratorAlgorithm);

                            byte[] encrypted = messageCipherWrapper.encrypt(messsage, key, cipherAlgorithm);
                            byte[] decrypted = messageCipherWrapper.decrypt(encrypted, key, cipherAlgorithm);

                            assertArrayEquals(decrypted, messsage);
                            result.get(provider).get(cipherAlgorithm).add(keyGeneratorAlgorithm);
                        } catch (Exception e) {
                            // ignore in case it failed to decode
                        }
                    });
                });
            }
        });

        ResultPrintUtil.print(result);
    }

    @Test
    public void encryptPublicKeyDecryptPrivateKey() throws Exception {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();

        Map<String, Map<String, List<String>>> result = new ConcurrentHashMap<>();

        byte[] messsage = CryptoByteUtils.randomString(56).getBytes("UTF-8");

        List<String> providers = jceProviderInfo.getAvailableProviders();

        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, MessageCipherWrapper.SERVICE)
                    && jceProviderInfo.isAvailableService(provider, AsymmetricKeyPairGenerator.SERVICE)) {

                result.put(provider, new ConcurrentHashMap<>());

                List<String> cipherAlgorithms = jceProviderInfo.getAvailableAlgorithm(provider, MessageCipherWrapper.SERVICE);
                List<String> keypairGeneratorAlgorithms = jceProviderInfo.getAvailableAlgorithm(provider, AsymmetricKeyPairGenerator.SERVICE);

                MessageCipherWrapper messageCipherWrapper = new MessageCipherWrapper(provider, cipherAlgorithms.get(0));
                AsymmetricKeyPairGenerator asymmetricKeyPairGenerator = new AsymmetricKeyPairGenerator(provider, keypairGeneratorAlgorithms.get(0));

                cipherAlgorithms.forEach(cipherAlgorithm -> {
                    result.get(provider).put(cipherAlgorithm, new Vector<>());
                    keypairGeneratorAlgorithms.forEach(keyGeneratorAlgorithm -> {
                        try {
                            KeyPair key = asymmetricKeyPairGenerator.newKeyPair(keyGeneratorAlgorithm);

                            byte[] encrypted = messageCipherWrapper.encrypt(messsage, key.getPublic(), cipherAlgorithm);
                            byte[] decrypted = messageCipherWrapper.decrypt(encrypted, key.getPrivate(), cipherAlgorithm);

                            assertArrayEquals(decrypted, messsage);
                            result.get(provider).get(cipherAlgorithm).add(keyGeneratorAlgorithm);
                        } catch (Exception e) {
                            // ignore in case it failed to decode
                        }
                    });
                });
            }
        });

        ResultPrintUtil.print(result);
    }

    @Test
    public void encryptPrivateKeyDecryptPublicKey() throws Exception {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();

        Map<String, Map<String, List<String>>> result = new ConcurrentHashMap<>();

        byte[] messsage = CryptoByteUtils.randomString(56).getBytes("UTF-8");

        List<String> providers = jceProviderInfo.getAvailableProviders();

        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, MessageCipherWrapper.SERVICE)
                    && jceProviderInfo.isAvailableService(provider, AsymmetricKeyPairGenerator.SERVICE)) {

                result.put(provider, new ConcurrentHashMap<>());

                List<String> cipherAlgorithms = jceProviderInfo.getAvailableAlgorithm(provider, MessageCipherWrapper.SERVICE);
                List<String> keypairGeneratorAlgorithms = jceProviderInfo.getAvailableAlgorithm(provider, AsymmetricKeyPairGenerator.SERVICE);

                MessageCipherWrapper messageCipherWrapper = new MessageCipherWrapper(provider, cipherAlgorithms.get(0));
                AsymmetricKeyPairGenerator asymmetricKeyPairGenerator = new AsymmetricKeyPairGenerator(provider, keypairGeneratorAlgorithms.get(0));

                cipherAlgorithms.forEach(cipherAlgorithm -> {
                    result.get(provider).put(cipherAlgorithm, new Vector<>());
                    keypairGeneratorAlgorithms.forEach(keyGeneratorAlgorithm -> {
                        try {
                            KeyPair key = asymmetricKeyPairGenerator.newKeyPair(keyGeneratorAlgorithm);

                            byte[] encrypted = messageCipherWrapper.encrypt(messsage, key.getPrivate(), cipherAlgorithm);
                            byte[] decrypted = messageCipherWrapper.decrypt(encrypted, key.getPublic(), cipherAlgorithm);

                            assertArrayEquals(decrypted, messsage);
                            result.get(provider).get(cipherAlgorithm).add(keyGeneratorAlgorithm);
                        } catch (Exception e) {
                            // ignore in case it failed to decode
                        }
                    });
                });
            }
        });

        ResultPrintUtil.print(result);
    }

    @Test
    public void toStringTest() {
        JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();
        List<String> providers = jceProviderInfo.getAvailableProviders();
        providers.forEach(provider -> {
            if(jceProviderInfo.isAvailableService(provider, MessageCipherWrapper.SERVICE)) {
                List<String> algorithms = jceProviderInfo.getAvailableAlgorithm(provider, MessageCipherWrapper.SERVICE);
                Collections.sort(algorithms);
                System.out.println(String.format("- %s", provider));
                System.out.println(String.format("%s", Arrays.toString(algorithms.toArray())));
            }
        });
    }*/
}