package com.bloomingbread.blockchain.crypto.keygenerator;

import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Enumeration;

public class ECWithNamedCurve {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        Enumeration e = ECNamedCurveTable.getNames();
        while(e.hasMoreElements()) {
            String name = (String) e.nextElement();
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(name);
            keyPairGenerationWithNamedCurve(spec.getName());
        }

        System.out.println("--------------------------------------------------------------");
        e = ECGOST3410NamedCurveTable.getNames();
        while(e.hasMoreElements()) {
            String name = (String) e.nextElement();
            ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(name);
            keyPairGenerationWithNamedCurve(spec.getName());
        }

    }

    private static void keyPairGenerationWithNamedCurve(final String curveName) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        g.initialize(ecSpec, new SecureRandom());
        KeyPair pair = g.generateKeyPair();

        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        System.out.println(String.format("[Public Key]  algorithm:%s, \tcurve name:%s, \tformat:%s, \tsize:%d", publicKey.getAlgorithm(), curveName, publicKey.getFormat(), publicKey.getEncoded().length));
        System.out.println(String.format("[Private Key] algorithm:%s, \tcurve name:%s, \tformat:%s, \tsize:%d", privateKey.getAlgorithm(), curveName, privateKey.getFormat(), privateKey.getEncoded().length));
        System.out.println();
    }
}
/*
suggested curve

  secp256k1 : SECG curve over a 256 bit prime field
  secp384r1 : NIST/SECG curve over a 384 bit prime field
  secp521r1 : NIST/SECG curve over a 521 bit prime field
  prime256v1: X9.62/SECG curve over a 256 bit prime field

ran in 19/Aug/2018
[Public Key]  algorithm:EC, 	curve name:c2pnb272w1, 	format:X.509, 	size:95
[Private Key] algorithm:EC, 	curve name:c2pnb272w1, 	format:PKCS#8, 	size:155

[Public Key]  algorithm:EC, 	curve name:c2tnb191v3, 	format:X.509, 	size:75
[Private Key] algorithm:EC, 	curve name:c2tnb191v3, 	format:PKCS#8, 	size:125

[Public Key]  algorithm:EC, 	curve name:c2pnb208w1, 	format:X.509, 	size:79
[Private Key] algorithm:EC, 	curve name:c2pnb208w1, 	format:PKCS#8, 	size:131

[Public Key]  algorithm:EC, 	curve name:c2tnb191v2, 	format:X.509, 	size:75
[Private Key] algorithm:EC, 	curve name:c2tnb191v2, 	format:PKCS#8, 	size:125

[Public Key]  algorithm:EC, 	curve name:c2tnb191v1, 	format:X.509, 	size:75
[Private Key] algorithm:EC, 	curve name:c2tnb191v1, 	format:PKCS#8, 	size:125

[Public Key]  algorithm:EC, 	curve name:prime192v3, 	format:X.509, 	size:75
[Private Key] algorithm:EC, 	curve name:prime192v3, 	format:PKCS#8, 	size:125

[Public Key]  algorithm:EC, 	curve name:c2tnb359v1, 	format:X.509, 	size:117
[Private Key] algorithm:EC, 	curve name:c2tnb359v1, 	format:PKCS#8, 	size:191

[Public Key]  algorithm:EC, 	curve name:prime192v2, 	format:X.509, 	size:75
[Private Key] algorithm:EC, 	curve name:prime192v2, 	format:PKCS#8, 	size:125

[Public Key]  algorithm:EC, 	curve name:prime192v1, 	format:X.509, 	size:75
[Private Key] algorithm:EC, 	curve name:prime192v1, 	format:PKCS#8, 	size:125

[Public Key]  algorithm:EC, 	curve name:c2tnb239v3, 	format:X.509, 	size:87
[Private Key] algorithm:EC, 	curve name:c2tnb239v3, 	format:PKCS#8, 	size:144

[Public Key]  algorithm:EC, 	curve name:c2pnb163v3, 	format:X.509, 	size:69
[Private Key] algorithm:EC, 	curve name:c2pnb163v3, 	format:PKCS#8, 	size:116

[Public Key]  algorithm:EC, 	curve name:c2tnb239v2, 	format:X.509, 	size:87
[Private Key] algorithm:EC, 	curve name:c2tnb239v2, 	format:PKCS#8, 	size:144

[Public Key]  algorithm:EC, 	curve name:c2pnb163v2, 	format:X.509, 	size:69
[Private Key] algorithm:EC, 	curve name:c2pnb163v2, 	format:PKCS#8, 	size:116

[Public Key]  algorithm:EC, 	curve name:c2tnb239v1, 	format:X.509, 	size:87
[Private Key] algorithm:EC, 	curve name:c2tnb239v1, 	format:PKCS#8, 	size:144

[Public Key]  algorithm:EC, 	curve name:c2pnb163v1, 	format:X.509, 	size:69
[Private Key] algorithm:EC, 	curve name:c2pnb163v1, 	format:PKCS#8, 	size:116

[Public Key]  algorithm:EC, 	curve name:c2pnb176w1, 	format:X.509, 	size:71
[Private Key] algorithm:EC, 	curve name:c2pnb176w1, 	format:PKCS#8, 	size:118

[Public Key]  algorithm:EC, 	curve name:prime256v1, 	format:X.509, 	size:91
[Private Key] algorithm:EC, 	curve name:prime256v1, 	format:PKCS#8, 	size:150

[Public Key]  algorithm:EC, 	curve name:c2pnb304w1, 	format:X.509, 	size:103
[Private Key] algorithm:EC, 	curve name:c2pnb304w1, 	format:PKCS#8, 	size:169

[Public Key]  algorithm:EC, 	curve name:c2pnb368w1, 	format:X.509, 	size:119
[Private Key] algorithm:EC, 	curve name:c2pnb368w1, 	format:PKCS#8, 	size:193

[Public Key]  algorithm:EC, 	curve name:c2tnb431r1, 	format:X.509, 	size:136
[Private Key] algorithm:EC, 	curve name:c2tnb431r1, 	format:PKCS#8, 	size:217

[Public Key]  algorithm:EC, 	curve name:prime239v3, 	format:X.509, 	size:87
[Private Key] algorithm:EC, 	curve name:prime239v3, 	format:PKCS#8, 	size:144

[Public Key]  algorithm:EC, 	curve name:prime239v2, 	format:X.509, 	size:87
[Private Key] algorithm:EC, 	curve name:prime239v2, 	format:PKCS#8, 	size:144

[Public Key]  algorithm:EC, 	curve name:prime239v1, 	format:X.509, 	size:87
[Private Key] algorithm:EC, 	curve name:prime239v1, 	format:PKCS#8, 	size:144

[Public Key]  algorithm:EC, 	curve name:sect283r1, 	format:X.509, 	size:96
[Private Key] algorithm:EC, 	curve name:sect283r1, 	format:PKCS#8, 	size:158

[Public Key]  algorithm:EC, 	curve name:sect283k1, 	format:X.509, 	size:96
[Private Key] algorithm:EC, 	curve name:sect283k1, 	format:PKCS#8, 	size:158

[Public Key]  algorithm:EC, 	curve name:sect163r2, 	format:X.509, 	size:66
[Private Key] algorithm:EC, 	curve name:sect163r2, 	format:PKCS#8, 	size:110

[Public Key]  algorithm:EC, 	curve name:secp256k1, 	format:X.509, 	size:88
[Private Key] algorithm:EC, 	curve name:secp256k1, 	format:PKCS#8, 	size:144

[Public Key]  algorithm:EC, 	curve name:secp160k1, 	format:X.509, 	size:64
[Private Key] algorithm:EC, 	curve name:secp160k1, 	format:PKCS#8, 	size:108

[Public Key]  algorithm:EC, 	curve name:secp160r1, 	format:X.509, 	size:64
[Private Key] algorithm:EC, 	curve name:secp160r1, 	format:PKCS#8, 	size:108

[Public Key]  algorithm:EC, 	curve name:secp112r2, 	format:X.509, 	size:52
[Private Key] algorithm:EC, 	curve name:secp112r2, 	format:PKCS#8, 	size:89

[Public Key]  algorithm:EC, 	curve name:secp112r1, 	format:X.509, 	size:52
[Private Key] algorithm:EC, 	curve name:secp112r1, 	format:PKCS#8, 	size:89

[Public Key]  algorithm:EC, 	curve name:sect113r2, 	format:X.509, 	size:54
[Private Key] algorithm:EC, 	curve name:sect113r2, 	format:PKCS#8, 	size:92

[Public Key]  algorithm:EC, 	curve name:sect113r1, 	format:X.509, 	size:54
[Private Key] algorithm:EC, 	curve name:sect113r1, 	format:PKCS#8, 	size:92

[Public Key]  algorithm:EC, 	curve name:sect239k1, 	format:X.509, 	size:84
[Private Key] algorithm:EC, 	curve name:sect239k1, 	format:PKCS#8, 	size:138

[Public Key]  algorithm:EC, 	curve name:secp128r2, 	format:X.509, 	size:56
[Private Key] algorithm:EC, 	curve name:secp128r2, 	format:PKCS#8, 	size:95

[Public Key]  algorithm:EC, 	curve name:sect163r1, 	format:X.509, 	size:66
[Private Key] algorithm:EC, 	curve name:sect163r1, 	format:PKCS#8, 	size:110

[Public Key]  algorithm:EC, 	curve name:secp128r1, 	format:X.509, 	size:56
[Private Key] algorithm:EC, 	curve name:secp128r1, 	format:PKCS#8, 	size:95

[Public Key]  algorithm:EC, 	curve name:sect233r1, 	format:X.509, 	size:84
[Private Key] algorithm:EC, 	curve name:sect233r1, 	format:PKCS#8, 	size:138

[Public Key]  algorithm:EC, 	curve name:sect163k1, 	format:X.509, 	size:66
[Private Key] algorithm:EC, 	curve name:sect163k1, 	format:PKCS#8, 	size:110

[Public Key]  algorithm:EC, 	curve name:sect233k1, 	format:X.509, 	size:84
[Private Key] algorithm:EC, 	curve name:sect233k1, 	format:PKCS#8, 	size:137

[Public Key]  algorithm:EC, 	curve name:sect193r2, 	format:X.509, 	size:74
[Private Key] algorithm:EC, 	curve name:sect193r2, 	format:PKCS#8, 	size:122

[Public Key]  algorithm:EC, 	curve name:sect193r1, 	format:X.509, 	size:74
[Private Key] algorithm:EC, 	curve name:sect193r1, 	format:PKCS#8, 	size:122

[Public Key]  algorithm:EC, 	curve name:sect131r2, 	format:X.509, 	size:58
[Private Key] algorithm:EC, 	curve name:sect131r2, 	format:PKCS#8, 	size:98

[Public Key]  algorithm:EC, 	curve name:sect131r1, 	format:X.509, 	size:58
[Private Key] algorithm:EC, 	curve name:sect131r1, 	format:PKCS#8, 	size:98

[Public Key]  algorithm:EC, 	curve name:secp256r1, 	format:X.509, 	size:91
[Private Key] algorithm:EC, 	curve name:secp256r1, 	format:PKCS#8, 	size:150

[Public Key]  algorithm:EC, 	curve name:sect571r1, 	format:X.509, 	size:170
[Private Key] algorithm:EC, 	curve name:sect571r1, 	format:PKCS#8, 	size:269

[Public Key]  algorithm:EC, 	curve name:sect571k1, 	format:X.509, 	size:170
[Private Key] algorithm:EC, 	curve name:sect571k1, 	format:PKCS#8, 	size:269

[Public Key]  algorithm:EC, 	curve name:secp192r1, 	format:X.509, 	size:75
[Private Key] algorithm:EC, 	curve name:secp192r1, 	format:PKCS#8, 	size:125

[Public Key]  algorithm:EC, 	curve name:sect409r1, 	format:X.509, 	size:128
[Private Key] algorithm:EC, 	curve name:sect409r1, 	format:PKCS#8, 	size:206

[Public Key]  algorithm:EC, 	curve name:sect409k1, 	format:X.509, 	size:128
[Private Key] algorithm:EC, 	curve name:sect409k1, 	format:PKCS#8, 	size:205

[Public Key]  algorithm:EC, 	curve name:secp521r1, 	format:X.509, 	size:158
[Private Key] algorithm:EC, 	curve name:secp521r1, 	format:PKCS#8, 	size:250

[Public Key]  algorithm:EC, 	curve name:secp384r1, 	format:X.509, 	size:120
[Private Key] algorithm:EC, 	curve name:secp384r1, 	format:PKCS#8, 	size:194

[Public Key]  algorithm:EC, 	curve name:secp224r1, 	format:X.509, 	size:80
[Private Key] algorithm:EC, 	curve name:secp224r1, 	format:PKCS#8, 	size:132

[Public Key]  algorithm:EC, 	curve name:secp224k1, 	format:X.509, 	size:80
[Private Key] algorithm:EC, 	curve name:secp224k1, 	format:PKCS#8, 	size:133

[Public Key]  algorithm:EC, 	curve name:secp192k1, 	format:X.509, 	size:72
[Private Key] algorithm:EC, 	curve name:secp192k1, 	format:PKCS#8, 	size:119

[Public Key]  algorithm:EC, 	curve name:secp160r2, 	format:X.509, 	size:64
[Private Key] algorithm:EC, 	curve name:secp160r2, 	format:PKCS#8, 	size:108

[Public Key]  algorithm:EC, 	curve name:B-163, 	format:X.509, 	size:66
[Private Key] algorithm:EC, 	curve name:B-163, 	format:PKCS#8, 	size:110

[Public Key]  algorithm:EC, 	curve name:P-521, 	format:X.509, 	size:158
[Private Key] algorithm:EC, 	curve name:P-521, 	format:PKCS#8, 	size:250

[Public Key]  algorithm:EC, 	curve name:P-256, 	format:X.509, 	size:91
[Private Key] algorithm:EC, 	curve name:P-256, 	format:PKCS#8, 	size:150

[Public Key]  algorithm:EC, 	curve name:K-163, 	format:X.509, 	size:66
[Private Key] algorithm:EC, 	curve name:K-163, 	format:PKCS#8, 	size:110

[Public Key]  algorithm:EC, 	curve name:B-233, 	format:X.509, 	size:84
[Private Key] algorithm:EC, 	curve name:B-233, 	format:PKCS#8, 	size:138

[Public Key]  algorithm:EC, 	curve name:P-224, 	format:X.509, 	size:80
[Private Key] algorithm:EC, 	curve name:P-224, 	format:PKCS#8, 	size:132

[Public Key]  algorithm:EC, 	curve name:P-384, 	format:X.509, 	size:120
[Private Key] algorithm:EC, 	curve name:P-384, 	format:PKCS#8, 	size:194

[Public Key]  algorithm:EC, 	curve name:K-233, 	format:X.509, 	size:84
[Private Key] algorithm:EC, 	curve name:K-233, 	format:PKCS#8, 	size:137

[Public Key]  algorithm:EC, 	curve name:B-409, 	format:X.509, 	size:128
[Private Key] algorithm:EC, 	curve name:B-409, 	format:PKCS#8, 	size:206

[Public Key]  algorithm:EC, 	curve name:B-283, 	format:X.509, 	size:96
[Private Key] algorithm:EC, 	curve name:B-283, 	format:PKCS#8, 	size:158

[Public Key]  algorithm:EC, 	curve name:B-571, 	format:X.509, 	size:170
[Private Key] algorithm:EC, 	curve name:B-571, 	format:PKCS#8, 	size:269

[Public Key]  algorithm:EC, 	curve name:K-409, 	format:X.509, 	size:128
[Private Key] algorithm:EC, 	curve name:K-409, 	format:PKCS#8, 	size:205

[Public Key]  algorithm:EC, 	curve name:K-283, 	format:X.509, 	size:96
[Private Key] algorithm:EC, 	curve name:K-283, 	format:PKCS#8, 	size:158

[Public Key]  algorithm:EC, 	curve name:P-192, 	format:X.509, 	size:75
[Private Key] algorithm:EC, 	curve name:P-192, 	format:PKCS#8, 	size:125

[Public Key]  algorithm:EC, 	curve name:K-571, 	format:X.509, 	size:170
[Private Key] algorithm:EC, 	curve name:K-571, 	format:PKCS#8, 	size:269

[Public Key]  algorithm:EC, 	curve name:brainpoolP224t1, 	format:X.509, 	size:84
[Private Key] algorithm:EC, 	curve name:brainpoolP224t1, 	format:PKCS#8, 	size:140

[Public Key]  algorithm:EC, 	curve name:brainpoolP512t1, 	format:X.509, 	size:158
[Private Key] algorithm:EC, 	curve name:brainpoolP512t1, 	format:PKCS#8, 	size:252

[Public Key]  algorithm:EC, 	curve name:brainpoolP224r1, 	format:X.509, 	size:84
[Private Key] algorithm:EC, 	curve name:brainpoolP224r1, 	format:PKCS#8, 	size:140

[Public Key]  algorithm:EC, 	curve name:brainpoolP512r1, 	format:X.509, 	size:158
[Private Key] algorithm:EC, 	curve name:brainpoolP512r1, 	format:PKCS#8, 	size:252

[Public Key]  algorithm:EC, 	curve name:brainpoolP192t1, 	format:X.509, 	size:76
[Private Key] algorithm:EC, 	curve name:brainpoolP192t1, 	format:PKCS#8, 	size:127

[Public Key]  algorithm:EC, 	curve name:brainpoolP384t1, 	format:X.509, 	size:124
[Private Key] algorithm:EC, 	curve name:brainpoolP384t1, 	format:PKCS#8, 	size:202

[Public Key]  algorithm:EC, 	curve name:brainpoolP192r1, 	format:X.509, 	size:76
[Private Key] algorithm:EC, 	curve name:brainpoolP192r1, 	format:PKCS#8, 	size:127

[Public Key]  algorithm:EC, 	curve name:brainpoolP384r1, 	format:X.509, 	size:124
[Private Key] algorithm:EC, 	curve name:brainpoolP384r1, 	format:PKCS#8, 	size:202

[Public Key]  algorithm:EC, 	curve name:brainpoolP160t1, 	format:X.509, 	size:68
[Private Key] algorithm:EC, 	curve name:brainpoolP160t1, 	format:PKCS#8, 	size:115

[Public Key]  algorithm:EC, 	curve name:brainpoolP320t1, 	format:X.509, 	size:108
[Private Key] algorithm:EC, 	curve name:brainpoolP320t1, 	format:PKCS#8, 	size:178

[Public Key]  algorithm:EC, 	curve name:brainpoolP160r1, 	format:X.509, 	size:68
[Private Key] algorithm:EC, 	curve name:brainpoolP160r1, 	format:PKCS#8, 	size:115

[Public Key]  algorithm:EC, 	curve name:brainpoolP320r1, 	format:X.509, 	size:108
[Private Key] algorithm:EC, 	curve name:brainpoolP320r1, 	format:PKCS#8, 	size:178

[Public Key]  algorithm:EC, 	curve name:brainpoolP256t1, 	format:X.509, 	size:92
[Private Key] algorithm:EC, 	curve name:brainpoolP256t1, 	format:PKCS#8, 	size:152

[Public Key]  algorithm:EC, 	curve name:brainpoolP256r1, 	format:X.509, 	size:92
[Private Key] algorithm:EC, 	curve name:brainpoolP256r1, 	format:PKCS#8, 	size:152

[Public Key]  algorithm:EC, 	curve name:FRP256v1, 	format:X.509, 	size:93
[Private Key] algorithm:EC, 	curve name:FRP256v1, 	format:PKCS#8, 	size:154

[Public Key]  algorithm:EC, 	curve name:Tc26-Gost-3410-12-256-paramSetA, 	format:X.509, 	size:92
[Private Key] algorithm:EC, 	curve name:Tc26-Gost-3410-12-256-paramSetA, 	format:PKCS#8, 	size:152

[Public Key]  algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetC, 	format:X.509, 	size:158
[Private Key] algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetC, 	format:PKCS#8, 	size:252

[Public Key]  algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-C, 	format:X.509, 	size:90
[Private Key] algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-C, 	format:PKCS#8, 	size:148

[Public Key]  algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetB, 	format:X.509, 	size:158
[Private Key] algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetB, 	format:PKCS#8, 	size:252

[Public Key]  algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-B, 	format:X.509, 	size:90
[Private Key] algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-B, 	format:PKCS#8, 	size:148

[Public Key]  algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetA, 	format:X.509, 	size:158
[Private Key] algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetA, 	format:PKCS#8, 	size:252

[Public Key]  algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-A, 	format:X.509, 	size:90
[Private Key] algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-A, 	format:PKCS#8, 	size:148

[Public Key]  algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-XchB, 	format:X.509, 	size:90
[Private Key] algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-XchB, 	format:PKCS#8, 	size:148

[Public Key]  algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-XchA, 	format:X.509, 	size:90
[Private Key] algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-XchA, 	format:PKCS#8, 	size:148

[Public Key]  algorithm:EC, 	curve name:wapip192v1, 	format:X.509, 	size:76
[Private Key] algorithm:EC, 	curve name:wapip192v1, 	format:PKCS#8, 	size:127

[Public Key]  algorithm:EC, 	curve name:sm2p256v1, 	format:X.509, 	size:91
[Private Key] algorithm:EC, 	curve name:sm2p256v1, 	format:PKCS#8, 	size:150

--------------------------------------------------------------
[Public Key]  algorithm:EC, 	curve name:Tc26-Gost-3410-12-256-paramSetA, 	format:X.509, 	size:92
[Private Key] algorithm:EC, 	curve name:Tc26-Gost-3410-12-256-paramSetA, 	format:PKCS#8, 	size:152

[Public Key]  algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetC, 	format:X.509, 	size:158
[Private Key] algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetC, 	format:PKCS#8, 	size:252

[Public Key]  algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-C, 	format:X.509, 	size:90
[Private Key] algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-C, 	format:PKCS#8, 	size:148

[Public Key]  algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetB, 	format:X.509, 	size:158
[Private Key] algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetB, 	format:PKCS#8, 	size:252

[Public Key]  algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-B, 	format:X.509, 	size:90
[Private Key] algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-B, 	format:PKCS#8, 	size:148

[Public Key]  algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetA, 	format:X.509, 	size:158
[Private Key] algorithm:EC, 	curve name:Tc26-Gost-3410-12-512-paramSetA, 	format:PKCS#8, 	size:252

[Public Key]  algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-A, 	format:X.509, 	size:90
[Private Key] algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-A, 	format:PKCS#8, 	size:148

[Public Key]  algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-XchB, 	format:X.509, 	size:90
[Private Key] algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-XchB, 	format:PKCS#8, 	size:148

[Public Key]  algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-XchA, 	format:X.509, 	size:90
[Private Key] algorithm:EC, 	curve name:GostR3410-2001-CryptoPro-XchA, 	format:PKCS#8, 	size:148
 */