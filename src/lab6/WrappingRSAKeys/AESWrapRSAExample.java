package lab6.WrappingRSAKeys;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * Exemplo para guardar uma chave RSA com chave AES.
 * A ideia � usar a chave AES como wrapping key da chave RSA (chave wrapped)
 */
public class AESWrapRSAExample
{
    public static void main(
        String[]    args)
		throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        SecureRandom random = new SecureRandom();
        
        KeyPairGenerator fact = KeyPairGenerator.getInstance("RSA", "BC");
        fact.initialize(2048, new SecureRandom());

        KeyPair     keyPair = fact.generateKeyPair();
        Key         wrapKey = Utils3.createKeyForAES(256, random);
        
        // wraping da chave RSA
        cipher.init(Cipher.WRAP_MODE, wrapKey);
        
        byte[] wrappedKey = cipher.wrap(keyPair.getPrivate());

        // unwraping da chave RSA 
        cipher.init(Cipher.UNWRAP_MODE, wrapKey);
        
        Key key = cipher.unwrap(wrappedKey, "RSA", Cipher.PRIVATE_KEY);

        if (keyPair.getPrivate().equals(key))
        {
            System.out.println("Chave recuperada com sucesso.");
        }
		else
		{
		    System.out.println("Erro na recupera��o da chave.");
		}
    }
}
