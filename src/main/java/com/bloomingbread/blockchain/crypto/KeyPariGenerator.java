package com.bloomingbread.blockchain.crypto;

import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.security.KeyFactory;
import java.util.Enumeration;

public class KeyPariGenerator {
    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());

        Enumeration e = ECNamedCurveTable.getNames();
        while(e.hasMoreElements()) {
            String name = (String) e.nextElement();
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(name);
            System.out.println(spec.getName());
        }

        System.out.println("--------------------------------------------------------------");
        e = ECGOST3410NamedCurveTable.getNames();
        while(e.hasMoreElements()) {
            String name = (String) e.nextElement();
            ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(name);
            System.out.println(spec.getName());
        }


/*
c2pnb272w1
c2tnb191v3
c2pnb208w1
c2tnb191v2
c2tnb191v1
prime192v3
c2tnb359v1
prime192v2
prime192v1
c2tnb239v3
c2pnb163v3
c2tnb239v2
c2pnb163v2
c2tnb239v1
c2pnb163v1
c2pnb176w1
prime256v1
c2pnb304w1
c2pnb368w1
c2tnb431r1
prime239v3
prime239v2
prime239v1
sect283r1
sect283k1
sect163r2
secp256k1
secp160k1
secp160r1
secp112r2
secp112r1
sect113r2
sect113r1
sect239k1
secp128r2
sect163r1
secp128r1
sect233r1
sect163k1
sect233k1
sect193r2
sect193r1
sect131r2
sect131r1
secp256r1
sect571r1
sect571k1
secp192r1
sect409r1
sect409k1
secp521r1
secp384r1
secp224r1
secp224k1
secp192k1
secp160r2
B-163
P-521
P-256
K-163
B-233
P-224
P-384
K-233
B-409
B-283
B-571
K-409
K-283
P-192
K-571
brainpoolP224t1
brainpoolP512t1
brainpoolP224r1
brainpoolP512r1
brainpoolP192t1
brainpoolP384t1
brainpoolP192r1
brainpoolP384r1
brainpoolP160t1
brainpoolP320t1
brainpoolP160r1
brainpoolP320r1
brainpoolP256t1
brainpoolP256r1
FRP256v1
Tc26-Gost-3410-12-256-paramSetA
Tc26-Gost-3410-12-512-paramSetC
GostR3410-2001-CryptoPro-C
Tc26-Gost-3410-12-512-paramSetB
GostR3410-2001-CryptoPro-B
Tc26-Gost-3410-12-512-paramSetA
GostR3410-2001-CryptoPro-A
GostR3410-2001-CryptoPro-XchB
GostR3410-2001-CryptoPro-XchA
wapip192v1
sm2p256v1
--------------------------------------------------------------
Tc26-Gost-3410-12-256-paramSetA
Tc26-Gost-3410-12-512-paramSetC
GostR3410-2001-CryptoPro-C
Tc26-Gost-3410-12-512-paramSetB
GostR3410-2001-CryptoPro-B
Tc26-Gost-3410-12-512-paramSetA
GostR3410-2001-CryptoPro-A
GostR3410-2001-CryptoPro-XchB
GostR3410-2001-CryptoPro-XchA
*/

        keyPairGenerationWithParameter();
        keyPairGenerationWithNamedCurve();

        usingKeyFactoryWithParameter();
        // usingKeyFactoryWithNamedCurve();
    }

    private static void keyPairGenerationWithParameter() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException  {
        ECCurve curve = new ECCurve.Fp(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec = new org.bouncycastle.jce.spec.ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair pair = g.generateKeyPair();

        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        System.out.println(String.format("%s, %s, %s", publicKey.getAlgorithm(), publicKey.getFormat(), Arrays.toString(publicKey.getEncoded())));
        System.out.println(String.format("%s, %s, %s", privateKey.getAlgorithm(), privateKey.getFormat(), Arrays.toString(privateKey.getEncoded())));
    }

    private static void keyPairGenerationWithNamedCurve() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException  {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp521r1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair pair = g.generateKeyPair();

        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        System.out.println(String.format("%s, %s, %s", publicKey.getAlgorithm(), publicKey.getFormat(), Arrays.toString(publicKey.getEncoded())));
        System.out.println(String.format("%s, %s, %s", privateKey.getAlgorithm(), privateKey.getFormat(), Arrays.toString(privateKey.getEncoded())));
    }

    private static void usingKeyFactoryWithParameter() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        ECCurve curve = new ECCurve.F2m(
                239, // m
                36, // k
                new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
                new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b
        ECParameterSpec params = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
                new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"), // n
                BigInteger.valueOf(4)); // h
        ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(
                new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
                params);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
                curve.decodePoint(Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
                params);

        KeyFactory f = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey privateKey = f.generatePrivate(priKeySpec);
        PublicKey  publicKey = f.generatePublic(pubKeySpec);

        System.out.println(String.format("%s, %s, %s", publicKey.getAlgorithm(), publicKey.getFormat(), Arrays.toString(publicKey.getEncoded())));
        System.out.println(String.format("%s, %s, %s", privateKey.getAlgorithm(), privateKey.getFormat(), Arrays.toString(privateKey.getEncoded())));
    }

//    private static void usingKeyFactoryWithNamedCurve() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException  {
//        ECNamedCurveParameterSpec namedSpec = ECNamedCurveTable.getParameterSpec("prime239v1");
//        AsymmetricKeyPairGenerator ecGen = AsymmetricKeyPairGenerator.getInstance("ECDSA", "BC");
//        ecGen.initialize(namedSpec);
//        KeyPair pair = ecGen.generateKeyPair();
//
//        ECCurve curve = namedSpec.getCurve() ;
//        ECParameterSpec params = new ECParameterSpec(curve, namedSpec.getG(), namedSpec.getN(), namedSpec.getH());
//
//
//        KeyFactory ecKeyFact = KeyFactory.getInstance("EC", "BC");
//
//        EllipticCurve ecCurve = new EllipticCurve(
//                new ECFieldFp(namedSpec.getCurve().getField().getCharacteristic()),
//                namedSpec.getCurve().getA().toBigInteger(), namedSpec.getCurve().getB().toBigInteger());
//
//
//        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
//                new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
//                namedSpec);
//        ECPublicKeySpec pubKey = new ECPublicKeySpec(
//                ECPointUtil.decodePoint(
//                        ecCurve,
//                        Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
//                params);
//    }


}
