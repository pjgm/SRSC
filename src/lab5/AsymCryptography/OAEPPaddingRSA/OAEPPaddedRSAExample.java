package lab5.AsymCryptography.OAEPPaddingRSA;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * RSA com uso de OAEP Padding + geracao de chave aleatoria
 * Notar que neste PAD e neste exemplo usa-se uma chave de no minimo 384 bits
 * Trata-se de um esquema de padding considerado dos mais seguros
 * OAEP - Optimal Asymmetric Encryption Padding
 * Esquema base:
 * M1=Mask( (H(P) || PS || 0x01 || M), S)
 * M2=Mask(S,M1)
 * Mp=0x00||M2||M1
 *                         Para Mask() ver MGF1
 */

public class OAEPPaddedRSAExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]           input = new byte[] { 0x00, (byte)0xAB, (byte)0xCD };
        Cipher	         cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        SecureRandom     random = Utils3.createFixedRandom();
        
        // gerar chaves
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

        generator.initialize(384, random);

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
