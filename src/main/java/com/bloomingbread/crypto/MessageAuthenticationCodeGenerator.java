package com.bloomingbread.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Message Authentication Code wrapper class
 *
 * 1) Create a symmetric key and share it between peers
 * 2) From the one side, create a mac with message and key
 * 3) Send message and mac
 * 4) From the other side, create another mac with message and key and compare mac from 3)
 *
 * Available Message Authentication Code algorithm in BC
 *
 * HMACGOST3411, HMACGOST3411-2012-256, HMACGOST3411-2012-512, HMACKECCAK224, HMACKECCAK256, HMACKECCAK288,
 * HMACKECCAK384, HMACKECCAK512, HMACMD2, HMACMD4, HMACMD5, HMACSHA1, PBEWITHHMACSHA, PBEWITHHMACSHA1,
 * HMACRIPEMD128, HMACRIPEMD160, PBEWITHHMACRIPEMD160, HMACRIPEMD256, HMACRIPEMD320, PBEWITHHMACSHA224,
 * HMACSHA224, PBEWITHHMACSHA256, HMACSHA256, OLDHMACSHA384, PBEWITHHMACSHA384, HMACSHA384, OLDHMACSHA512,
 * PBEWITHHMACSHA512, HMACSHA512, HMACSHA512/224, HMACSHA512/256, HMACSHA3-224, HMACSHA3-256, HMACSHA3-384,
 * HMACSHA3-512, HMACSkein-256-128, HMACSkein-256-160, HMACSkein-256-224, HMACSkein-256-256, HMACSkein-512-128,
 * HMACSkein-512-160, HMACSkein-512-224, HMACSkein-512-256, HMACSkein-512-384, HMACSkein-512-512, HMACSkein-1024-384,
 * HMACSkein-1024-512, HMACSkein-1024-1024, Skein-MAC-256-128, Skein-MAC-256-160, Skein-MAC-256-224, Skein-MAC-256-256,
 * Skein-MAC-512-128, Skein-MAC-512-160, Skein-MAC-512-224, Skein-MAC-512-256, Skein-MAC-512-384,
 * Skein-MAC-512-512, Skein-MAC-1024-384, Skein-MAC-1024-512, Skein-MAC-1024-1024, HMACTIGER, HMACWHIRLPOOL,
 * HMACDSTU7564-256, HMACDSTU7564-384, HMACDSTU7564-512, SIPHASH-2-4, SIPHASH-4-8, POLY1305, AESCMAC, AESCCMMAC,
 * AES-GMAC, POLY1305-AES, ARIA-GMAC, POLY1305-ARIA, BLOWFISHCMAC, CAMELLIA-GMAC, POLY1305-CAMELLIA, CAST6-GMAC,
 * POLY1305-CAST6, DESCMAC, DESMAC, DESMAC/CFB8, DESMAC64, DESMAC64WITHISO7816-4PADDING, DESWITHISO9797, ISO9797ALG3MAC,
 * ISO9797ALG3WITHISO7816-4PADDING, DESEDECMAC, DESEDEMAC, DESEDEMAC/CFB8, DESEDEMAC64, DESEDEMAC64WITHISO7816-4PADDING,
 * GOST28147MAC, IDEAMAC, IDEAMAC/CFB8, NOEKEON-GMAC, POLY1305-NOEKEON, RC2MAC, RC2MAC/CFB8, RC5MAC, RC5MAC/CFB8,
 * RC6-GMAC, POLY1305-RC6, SEED-CMAC, SEED-GMAC, POLY1305-SEED, SERPENT-GMAC, TNEPRES-GMAC, POLY1305-SERPENT,
 * Shacal-2CMAC, SKIPJACKMAC, SKIPJACKMAC/CFB8, SM4-CMAC, SM4-GMAC, POLY1305-SM4, Twofish-GMAC, POLY1305-Twofish,
 * Threefish-256CMAC, Threefish-512CMAC, Threefish-1024CMAC, VMPCMAC, DSTU7624GMAC, DSTU7624-128GMAC, DSTU7624-256GMAC,
 * DSTU7624-512GMAC, GOST3412MAC
 */
public class MessageAuthenticationCodeGenerator extends CryptoBase {
    public static final String SERVICE = "Mac";
    public static final String DEFAULT_ALGORITHM = "HMACSHA512";

    public MessageAuthenticationCodeGenerator(final String providerName) {
        super(providerName, SERVICE);
    }

    public MessageAuthenticationCodeGenerator() {
        super(BouncyCastleProvider.PROVIDER_NAME, SERVICE);
    }

    public static byte[] getAuthenticationCode(final byte[] message, final String algorithm, final SecretKey secretKey) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        mac.init(secretKey);
        mac.update(message);
        return mac.doFinal();
    }
}