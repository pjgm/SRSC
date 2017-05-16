package labs.pbencryption;
// Este programa mostra a utilizacao um esquema usual com chave
// pre-calculada (ou ja existente) para cifrar
// dados usando depois PBE para decifrar esses dados. A password usada 
// serve para criar uma chave com PBEKeySpec,
// convertida para uma chave de facto com SecretKeyFactory. O salt e
// o iterador sao passados com a chave pre-processada com PBEParameterSpec


import labs.EncryptDecrypt.ex2.Utils;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Demonstracao de uso do esquema PBE com parametros (explicitos)
 */
public class PBEOtherExample
{
    public static void main(String[]    args)
        throws Exception
    {

	if (args.length==0) {
	    System.err.println("Use: PBEOtherExample <password>");
	    System.exit(-1);
	}

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

        System.out.println("plaintext  : " + Utils.toHex(input));


        char[] password = args[0].toCharArray();
        byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae };
        int                 iterationCount = 2048;       
        PBEKeySpec          pbeSpec = new PBEKeySpec(password);
        SecretKeyFactory    keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
        Key sKey= keyFact.generateSecret(pbeSpec);

        // Cifrar com esquema PBE

        Cipher cEnc = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
        cEnc.init(Cipher.ENCRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));

        byte[] out = cEnc.doFinal(input);
       
        // Decifrar com esquema PBE
        // Decifrar passando explicitamente os parametros de salt e iterador
       
        Cipher cDec = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
        cDec.init(Cipher.DECRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));

        System.out.println("-------------------------------------------------");
        System.out.println("gen key    : " + Utils.toHex(sKey.getEncoded()));
        System.out.println("gen iv     : " + Utils.toHex(cDec.getIV()));
        System.out.println("key format : " + sKey.getFormat());
        System.out.println("key alg    : " + sKey.getAlgorithm());
        System.out.println("ciphertext : " + Utils.toHex(out));
        System.out.println("plaintext  : " + Utils.toHex(cDec.doFinal(out)));
        System.out.println("-------------------------------------------------");
    }
}
