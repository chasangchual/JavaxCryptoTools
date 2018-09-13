package com.bloomingbread.blockchain.crypto.keygenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;

/**
 *
 * AES, AESWRAP, AESWRAPPAD, AESRFC3211WRAP, AESRFC5649WRAP, CCM, GCM, PBEWITHSHAAND128BITAES-CBC-BC,
 * PBEWITHSHAAND192BITAES-CBC-BC, PBEWITHSHAAND256BITAES-CBC-BC, PBEWITHSHA256AND128BITAES-CBC-BC,
 * PBEWITHSHA256AND192BITAES-CBC-BC, PBEWITHSHA256AND256BITAES-CBC-BC, PBEWITHMD5AND128BITAES-CBC-OPENSSL,
 * PBEWITHMD5AND192BITAES-CBC-OPENSSL, PBEWITHMD5AND256BITAES-CBC-OPENSSL, ARC4, PBEWITHSHAAND128BITRC4,
 * PBEWITHSHAAND40BITRC4, ARIA, ARIARFC3211WRAP, ARIAWRAP, ARIAWRAPPAD, BLOWFISH, CAMELLIA, CAMELLIARFC3211WRAP,
 * CAMELLIAWRAP, CAST5, CAST6, CHACHA, CHACHA7539, DES, DESRFC3211WRAP, PBEWITHMD2ANDDES, PBEWITHMD5ANDDES,
 * PBEWITHSHA1ANDDES, DESEDE, DESEDEWRAP,DESEDERFC3211WRAP, PBEWITHSHAAND3-KEYTRIPLEDES-CBC,
 * BROKENPBEWITHSHAAND3-KEYTRIPLEDES-CBC, OLDPBEWITHSHAAND3-KEYTRIPLEDES-CBC, PBEWITHSHAAND2-KEYTRIPLEDES-CBC,
 * BROKENPBEWITHSHAAND2-KEYTRIPLEDES-CBC, GOST28147, Grainv1, Grain128, HC128, HC256, IDEA, PBEWITHSHAANDIDEA-CBC,
 * NOEKEON, RC2, RC2WRAP, PBEWITHMD5ANDRC2, PBEWITHSHA1ANDRC2, PBEWITHSHAAND128BITRC2-CBC, PBEWITHSHAAND40BITRC2-CBC,
 * RC5, RC5-64, RC6, RIJNDAEL, SALSA20, SEED, SEEDWRAP, Serpent, Tnepres, Shacal2, SHACAL-2, SKIPJACK, SM4, TEA,
 * Twofish, PBEWITHSHAANDTWOFISH-CBC, Threefish-256, Threefish-512, Threefish-1024, VMPC, VMPC-KSA3, XTEA, XSALSA20,
 * DSTU7624, DSTU7624-128, DSTU7624-256, DSTU7624-512, DSTU7624KW, DSTU7624-128KW, DSTU7624-256KW, DSTU7624-512KW,
 * GOST3412-2015, GOST3412-2015/CFB, GOST3412-2015/CFB8, GOST3412-2015/OFB, GOST3412-2015/CBC, GOST3412-2015/CTR, IES,
 * IESwithAES-CBC, IESWITHDESEDE-CBC, DHIES, DHIESwithAES-CBC, DHIESWITHDESEDE-CBC, ECIES, ECIESwithAES-CBC,
 * ECIESwithDESEDE-CBC, RSA, RSA/RAW, RSA/PKCS1, RSA/1, RSA/2, RSA/OAEP, RSA/ISO9796-1, ELGAMAL, ELGAMAL/PKCS1,
 * BROKENPBEWITHMD5ANDDES, BROKENPBEWITHSHA1ANDDES, OLDPBEWITHSHAANDTWOFISH-CBC]
 */

public class MessageCipherWrapper extends CryptoBase {
    public static final String SERVICE = "Cipher";
    public static final String DEFAULT_ALGORITHM = "AES";

    public MessageCipherWrapper() {
        this(BouncyCastleProvider.PROVIDER_NAME, DEFAULT_ALGORITHM);
    }

    public MessageCipherWrapper(final String providerName, final String initialAlgorithm) {
        super(providerName, SERVICE, initialAlgorithm);
    }

    public byte[] encrypt(final byte[] message, final SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encrypt(message, key, DEFAULT_ALGORITHM);
    }

    public byte[] encrypt(final byte[] message, final SecretKey key, final String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        updateRecentlyUsedAlgorithm(algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public byte[] encrypt(final byte[] message, final PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encrypt(message, key, recentAlgorithm);
    }

    public byte[] encrypt(final byte[] message, final PublicKey key, final String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        updateRecentlyUsedAlgorithm(algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public byte[] encrypt(final byte[] message, final PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encrypt(message, key, recentAlgorithm);
    }

    public byte[] encrypt(final byte[] message, final PrivateKey key, final String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        updateRecentlyUsedAlgorithm(algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public byte[] decrypt(final byte[] message, final SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return decrypt(message, key, recentAlgorithm);
    }

    public byte[] decrypt(final byte[] message, final SecretKey key, final String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        updateRecentlyUsedAlgorithm(algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public byte[] decrypt(final byte[] message, final PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return decrypt(message, key, recentAlgorithm);
    }

    public byte[] decrypt(final byte[] message, final PublicKey key, final String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        updateRecentlyUsedAlgorithm(algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    public byte[] decrypt(final byte[] message, final PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return decrypt(message, key, recentAlgorithm);
    }

    public byte[] decrypt(final byte[] message, final PrivateKey key, final String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        updateRecentlyUsedAlgorithm(algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(message);
    }
}