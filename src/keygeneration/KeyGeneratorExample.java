package keygeneration;// A utilizacao da classe SecretKeySpec permite criar chaves
// simetricas, que depois sao passadas para o passo de cifra
// usando Cipher.init() 
// Por outro lado atraves da geracao de vectores de inicializacao
// pode perceber-se que sera possivel gerar chaves simplesmente gerando 
// um array de bytes random e passando esses bytes a SecretKeySpec
// Mas um modo mais preferivel em ultima instancia para gerar chaves
// simetricas consiste em usar a classe KeyGenerator, como se pode
// discutir com este exemplo.


import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Exemplo de utilizacao da classe KeyGenerator
 * e demonstracao da criacao de chaves SecretKeySpec e
 * codificacao de chaves simetricas
 */
public class KeyGeneratorExample
{   
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]          input = new byte[] { 
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        byte[]		    ivBytes = new byte[] { 
                            0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        
        // Vamos usar AES, modo CTR sem padding com o provedor indicado

        //Cipher          cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        Cipher          cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        KeyGenerator    generator = KeyGenerator.getInstance("AES", "BC");

       generator.init(192);
        
        Key encryptionKey = generator.generateKey(); // Gera chave

        System.out.println("------------------------------------------------------");
        System.out.println("key alg : " + encryptionKey.getAlgorithm());
        System.out.println("key format : " + encryptionKey.getFormat());
        System.out.println("key   : " + Utils.toHex(encryptionKey.getEncoded()));
        System.out.println("------------------------------------------------------");        
        System.out.println("input : " + Utils.toHex(input));
        
        // Cifrar com a chave gerada
        
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
        
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        
        ctLength += cipher.doFinal(cipherText, ctLength);
        
        // Decifrar com a chave gerada
        
        Key	decryptionKey = new SecretKeySpec(encryptionKey.getEncoded(), encryptionKey.getAlgorithm());
        
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));
        
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];

        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        
        ptLength += cipher.doFinal(plainText, ptLength);
        
        System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }
}
