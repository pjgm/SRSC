package labs.lab6.KeyExchangeRef;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class RSAKeyExchangeExample
{
    private static byte[] packKeyAndIv(
        Key	            key,
        IvParameterSpec ivSpec)
        throws IOException
    {
        ByteArrayOutputStream	bOut = new ByteArrayOutputStream();
        
        bOut.write(ivSpec.getIV());
        bOut.write(key.getEncoded());
        
        return bOut.toByteArray();
    }
    
    private static Object[] unpackKeyAndIV(
        byte[]    data)
    {
        byte[]    keyD = new byte[16];
        byte[]    iv = new byte[data.length - 16];
        
        return new Object[] {
             new SecretKeySpec(data, 16, data.length - 16, "AES"),
             new IvParameterSpec(data, 0, 16)
        };
    }
    
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]           input = new byte[] 
  	                 { 0x00, (byte)0xbe, (byte)0xef,
                           0x00, (byte)0xbe, (byte)0xef
                          };
        SecureRandom     random = Utils3.createFixedRandom();
        
        // Criacao de chaves RSA
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        
        generator.initialize(1024, random);

        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        System.out.println("input            : " + Utils3.toHex(input));
        
        // Criar chave simetrica e vector de inicializacao
        Key             sKey = Utils3.createKeyForAES(256, random);
        IvParameterSpec sIvSpec = Utils3.createCtrIvForAES(0, random);
        
        // symmetric key/iv wrapping com a cripto assimetrica RSA
        Cipher	        xCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        
        xCipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        
        byte[]          keyBlock = xCipher.doFinal(packKeyAndIv(sKey, sIvSpec));
        
        // Cifrar os dados 
        Cipher          sCipher	= Cipher.getInstance("AES/CTR/NoPadding", "BC");	
        
        sCipher.init(Cipher.ENCRYPT_MODE, sKey, sIvSpec);

        byte[] cipherText = sCipher.doFinal(input);

        System.out.println("keyBlock length  : " + keyBlock.length);
        System.out.println("cipherText length: " + cipherText.length);
        
        // symmetric key/iv unwrapping com cripto assimetrica
        xCipher.init(Cipher.DECRYPT_MODE, privKey);
        
        Object[]	keyIv = unpackKeyAndIV(xCipher.doFinal(keyBlock));
        
        // deifra dos dados M
        sCipher.init(Cipher.DECRYPT_MODE, (Key)keyIv[0], (IvParameterSpec)keyIv[1]);

        byte[] plainText = sCipher.doFinal(cipherText);
        
        System.out.println("plain            : " + Utils3.toHex(plainText));
    }
}
