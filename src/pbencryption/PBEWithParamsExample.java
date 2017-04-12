
// Este programa mostra a utiliza‡ao de um esquema usual com chave
// pre-calculada (ou ja existente) para cifrar
// dados usando depois PBE para decifrar esses dados. A password usada 
// serve para criar uma chave com PBEKeySpec,
// convertida para uma chave de facto com SecretKeyFactory. O salt e
// o iterador sao passados com a chave pre-processada com PBEParameterSpec


import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Demonstracao de uso do esquema PBE com parametros (explicitos)
 */
public class PBEWithParamsExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]          input = new byte[] { 
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[]          keyBytes = new byte[] { 
                            0x73, 0x2f, 0x2d, 0x33, (byte)0xc8, 0x01, 0x73, 
                            0x2b, 0x72, 0x06, 0x75, 0x6c, (byte)0xbd, 0x44, 
                            (byte)0xf9, (byte)0xc1, (byte)0xc1, 0x03, (byte)0xdd, 
                            (byte)0xd9, 0x7c, 0x7c, (byte)0xbe, (byte)0x8e };
        byte[]		    ivBytes = new byte[] { 
                            (byte)0xb0, 0x7b, (byte)0xf5, 0x22, (byte)0xc8, 
                            (byte)0xd6, 0x08, (byte)0xb8 };

        System.out.println("input plaintext : " + Utils.toHex(input));
       

	// Cifrar dados com chaves pre calculadas de forma usual
	// 3DES, modo CBC, Padding PKCS7, usando o provedor indicado
        
	// Cipher cEnc = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");
        Cipher cEnc = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");

        cEnc.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(keyBytes, "DESede"),
            new IvParameterSpec(ivBytes));

        byte[] out = cEnc.doFinal(input);
       
        // Decifrar com esquema PBE

        
        char[]              password = "password".toCharArray();
        byte[]              salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae };

        int                 iterationCount = 2048;
       
        // para a pbeSpec vamos usar apenas a password, mas nao o
	// salt nem o iterador
       
        PBEKeySpec          pbeSpec = new PBEKeySpec(password);
        SecretKeyFactory    keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");

        Cipher cDec = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES","BC");
        Key    sKey = keyFact.generateSecret(pbeSpec);

        // Decifrar passando explicitamente os parametros de salt e iterador
       
        cDec.init(Cipher.DECRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));
        

        System.out.println("cipher : " + Utils.toHex(out));
        System.out.println("gen key: " + Utils.toHex(sKey.getEncoded()));
        System.out.println("gen iv : " + Utils.toHex(cDec.getIV()));
        System.out.println("plain  : " + Utils.toHex(cDec.doFinal(out)));
    }
}
