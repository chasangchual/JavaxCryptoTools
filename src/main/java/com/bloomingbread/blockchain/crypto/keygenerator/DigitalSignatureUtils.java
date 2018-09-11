package com.bloomingbread.blockchain.crypto.keygenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.plugin2.message.Message;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * DSA, NONEWITHDSA, DETDSA, SHA1WITHDETDSA, SHA224WITHDETDSA, SHA256WITHDETDSA, SHA384WITHDETDSA, SHA512WITHDETDSA,
 * DDSA, SHA1WITHDDSA, SHA224WITHDDSA, SHA256WITHDDSA, SHA384WITHDDSA, SHA512WITHDDSA, SHA3-224WITHDDSA, SHA3-256WITHDDSA,
 * SHA3-384WITHDDSA, SHA3-512WITHDDSA, SHA224WITHDSA, SHA256WITHDSA, SHA384WITHDSA, SHA512WITHDSA, SHA3-224WITHDSA,
 * SHA3-256WITHDSA, SHA3-384WITHDSA, SHA3-512WITHDSA, ECDSA, NONEwithECDSA, ECDDSA, SHA1WITHECDDSA, SHA224WITHECDDSA,
 * SHA256WITHECDDSA, SHA384WITHECDDSA, SHA512WITHECDDSA, SHA3-224WITHECDDSA, SHA3-256WITHECDDSA, SHA3-384WITHECDDSA,
 * SHA3-512WITHECDDSA, SHA224WITHECDSA, SHA256WITHECDSA, SHA384WITHECDSA, SHA512WITHECDSA, SHA3-224WITHECDSA,
 * SHA3-256WITHECDSA, SHA3-384WITHECDSA, SHA3-512WITHECDSA, RIPEMD160WITHECDSA, SHA1WITHECNR, SHA224WITHECNR,
 * SHA256WITHECNR, SHA384WITHECNR, SHA512WITHECNR, SHA1WITHCVC-ECDSA, SHA224WITHCVC-ECDSA, SHA256WITHCVC-ECDSA,
 * SHA384WITHCVC-ECDSA, SHA512WITHCVC-ECDSA, SHA1WITHPLAIN-ECDSA, SHA224WITHPLAIN-ECDSA, SHA256WITHPLAIN-ECDSA,
 * SHA384WITHPLAIN-ECDSA, SHA512WITHPLAIN-ECDSA, RIPEMD160WITHPLAIN-ECDSA, RSASSA-PSS,
 * RSA, RAWRSASSA-PSS, SHA224WITHRSAANDMGF1, SHA256WITHRSAANDMGF1, SHA384WITHRSAANDMGF1, SHA512WITHRSAANDMGF1,
 * SHA512(224)WITHRSAANDMGF1, SHA512(256)WITHRSAANDMGF1, SHA3-224WITHRSAANDMGF1, SHA3-256WITHRSAANDMGF1,
 * SHA3-384WITHRSAANDMGF1, SHA3-512WITHRSAANDMGF1, MD2WITHRSA, MD4WITHRSA, MD5WITHRSA, MD5WITHRSA/ISO9796-2,
 * SHA1WITHRSAANDMGF1, SHA1WITHRSA, SHA1WITHRSA/ISO9796-2, SHA1WITHRSA/X9.31, SHA224WITHRSA, SHA256WITHRSA,
 * SHA384WITHRSA, SHA512WITHRSA, SHA512(224)WITHRSA, SHA512(256)WITHRSA, SHA3-224WITHRSA, SHA3-256WITHRSA,
 * SHA3-384WITHRSA, SHA3-512WITHRSA, SHA224WITHRSA/ISO9796-2, SHA256WITHRSA/ISO9796-2, SHA384WITHRSA/ISO9796-2,
 * SHA512WITHRSA/ISO9796-2, SHA512(224)WITHRSA/ISO9796-2, SHA512(256)WITHRSA/ISO9796-2, SHA224WITHRSA/X9.31,
 * SHA256WITHRSA/X9.31, SHA384WITHRSA/X9.31, SHA512WITHRSA/X9.31, SHA512(224)WITHRSA/X9.31, SHA512(256)WITHRSA/X9.31,
 * RIPEMD128WITHRSA, RMD128WITHRSA, RMD128WITHRSA/X9.31, RIPEMD128WITHRSA/X9.31, RIPEMD160WITHRSA, RMD160WITHRSA,
 * RIPEMD160withRSA/ISO9796-2, RMD160WITHRSA/X9.31, RIPEMD160WITHRSA/X9.31, RIPEMD256WITHRSA, RMD256WITHRSA,
 * WhirlpoolWITHRSA/ISO9796-2, WhirlpoolWITHRSA/X9.31, GOST3410, ECGOST3410, GOST3411WITHECGOST3410, ECGOST3410-2012-256,
 * GOST3411-2012-256WITHECGOST3410-2012-256, ECGOST3410-2012-512, GOST3411-2012-512WITHECGOST3410-2012-512, DSTU4145,
 * GOST3411WITHDSTU4145LE, GOST3411WITHDSTU4145, SM3WITHSM2
 */
public class DigitalSignatureUtils  extends CryptoBase {
    public static final String SIGNATURE_SEVICE = "Signature";
    public static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256WITHECDDSA";

    public DigitalSignatureUtils() {
        this(BouncyCastleProvider.PROVIDER_NAME);
    }

    public DigitalSignatureUtils(final String providerName) {
        super(providerName, SIGNATURE_SEVICE, DEFAULT_SIGNATURE_ALGORITHM);
    }

    public byte[] generateSignature(final byte[] message, final PrivateKey key) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return generateSignature(message, recentAlgorithm, key);
    }

    public byte[] generateSignature(final byte[] message, final String algorithm, final PrivateKey key)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initSign(key);
        sig.update(message);
        byte[] signed = sig.sign();

        return signed;
    }

    public boolean veriySignature(final byte[] message, final byte[] signature, final PublicKey key)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        return veriySignature(message, signature, recentAlgorithm, key);
    }

    public boolean veriySignature(final byte[] message, final byte[] signature, final String algorithm, final PublicKey key)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(key);
        sig.update(message);
        boolean result = sig.verify(signature);
        return result;
    }
}