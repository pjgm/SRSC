package lab5.AsymCryptography.SimplesBaseRSA;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;

/**
 * Basic RSA example.
 */
public class BaseRSAExample {
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]           input = new byte[] { (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78 };
        Cipher	         cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        KeyFactory       keyFactory = KeyFactory.getInstance("RSA", "BC");
        
        // criar as chaves (com base me informacao gerida de forma manual)

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("11", 16));
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),  
                new BigInteger("57791d5430d593164082036ad8b29fb1", 16));
        
        RSAPublicKey pubKey = (RSAPublicKey)keyFactory.generatePublic(pubKeySpec);
        RSAPrivateKey privKey = (RSAPrivateKey)keyFactory.generatePrivate(privKeySpec);

        System.out.println("input : " + Utils3.toHex(input));

        // Cifrar com publica ...
        
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        byte[] cipherText1 = cipher.doFinal(input);

        System.out.println("cipher: " + Utils3.toHex(cipherText1));
        
        // Decifrar com privada

        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] plainText1 = cipher.doFinal(cipherText1);
        
        System.out.println("plain : " + Utils3.toHex(plainText1));
       
       
       
        // Cifrar com privada
        
        cipher.init(Cipher.ENCRYPT_MODE, privKey);

        byte[] cipherText2 = cipher.doFinal(input);

        System.out.println("cipher: " + Utils3.toHex(cipherText2));
        
        // Decifrar com publica

        cipher.init(Cipher.DECRYPT_MODE, pubKey);

        byte[] plainText2 = cipher.doFinal(cipherText2);
        
        System.out.println("plain : " + Utils3.toHex(plainText2));
       
       
    }
}
