package labs.lab5.AsymCryptography.RandomKeyRSA;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * RSA mas com geracao aleatoria de chaves
 */
public class RandomKeyRSAExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]           input = new byte[] { (byte)0x09, (byte)0xAB, (byte)0xCD, (byte)0xEF };
        Cipher	         cipher = Cipher.getInstance("RSA/NONE/NoPadding", "BC");
        SecureRandom     random = Utils3.createFixedRandom();
        

	// Criar par de chaves
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        
        generator.initialize(256, random);

        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        System.out.println("input : " + Utils3.toHex(input));
        

	// Cifrar
        
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils3.toHex(cipherText));
        

	// Decifrar

        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] plainText = cipher.doFinal(cipherText);
        
        System.out.println("plain : " + Utils3.toHex(plainText));
    }
}
