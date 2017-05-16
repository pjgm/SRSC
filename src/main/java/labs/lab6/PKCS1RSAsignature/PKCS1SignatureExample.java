package labs.lab6.PKCS1RSAsignature;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * Geracao de uma assinatura de uma mensagem com RSA
 * no esquema PKCS1 
 * Este esquema usa uma assinatura de uma sintese SHA1 da mensagem que
 * se pretende assinar
 */
public class PKCS1SignatureExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        
        keyGen.initialize(512, new SecureRandom());
        
        KeyPair             keyPair = keyGen.generateKeyPair();
        Signature           signature = Signature.getInstance("SHA1withRSA", "BC");

        // gerer objecto  signature
        signature.initSign(keyPair.getPrivate(), Utils3.createFixedRandom());

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' , (byte) 125 };

        signature.update(message);

        byte[]  sigBytes = signature.sign();
        
        // Verificar - neste caso estamos a obter a chave publica do par mas
	// em geral usamos a chave publica que previamente conhecemos de
	// quem assinou.
	// 
        signature.initVerify(keyPair.getPublic());

        signature.update(message);

        if (signature.verify(sigBytes))
        {
            System.out.println("Assinatura validada - reconhecida");
        }
        else
        {
            System.out.println("Assinatura nao reconhecida");
        }
    }
}
