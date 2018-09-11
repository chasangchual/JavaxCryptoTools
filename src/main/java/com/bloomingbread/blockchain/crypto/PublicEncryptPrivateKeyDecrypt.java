package com.bloomingbread.blockchain.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

public class PublicEncryptPrivateKeyDecrypt {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            String stringToEncrypt = PublicEncryptPrivateKeyDecrypt.class.getCanonicalName();
            KeyPair keyPair = generateKeyPair();
            byte[] ciperText = encrypt(keyPair.getPublic(), stringToEncrypt.getBytes());
            byte[] plainText = decrypt(keyPair.getPrivate(), ciperText);
            System.out.println(stringToEncrypt);
            System.out.println(new String(ciperText));
            System.out.println(new String(plainText));
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public static KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("brainpoolP384r1");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(ecSpec, new SecureRandom());
        return generator.generateKeyPair();
//        KeyPair pair = generator.generateKeyPair();
//
//        PublicKey publicKey = pair.getPublic();
//        PrivateKey privateKey = pair.getPrivate();
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] plaintext) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher iesCipher = Cipher.getInstance("ECIESwithAES");
        iesCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ciphertext = iesCipher.doFinal(plaintext);
        return ciphertext;
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher iesCipher = Cipher.getInstance("ECIESwithAES");
        iesCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plaintext = iesCipher.doFinal(cipherText);
        return plaintext;
    }
}
