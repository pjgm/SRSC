package EncryptDecrypt.ex2; /**
 * Materiais/Labs para SRSC 16/17, Sem-2
 * Henrique Domingos, 12/3/17
 **/

// ReceiveDecrypt.java 
// Recebe e decifra 

import java.io.*;
import java.net.*;
import java.security.spec.KeySpec;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

/**
 * Decifra
 */
public class ReceiveDecrypt {

  public static void main(String args[]) throws Exception {

    Integer  port=9999; // Default, mude se quizer

    // Parametros para decifrar (de acordo com o emissor)
    // Se quizer mude passando os parametros
    String ciphersuite="AES/CTR/PKCS7Padding";
    String provedor="BC";

    if (args.length==1) {
	port=Integer.parseInt(args[0]);
    }

    if (args.length==2) {
	port=Integer.parseInt(args[0]);
        ciphersuite=args[1];
    }

    if (args.length==3) {
	port=Integer.parseInt(args[0]);
        ciphersuite=args[1];
        provedor=args[2];
    }

    // ok este IV foi o usado pelo emissor ...
    byte[] ivBytes= new byte[] {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
    };
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

    System.out.println("\nEsperar cyphertext no porto: " +port);
    System.out.println("Ciphersuite:" +ciphersuite +" Provedor: "+provedor);
    System.out.println();

    // Ler chave secreta
    SecretKey key = KeyRing.readSecretKey();
    byte[] ciphertext = null;


    for(;;)
    {
    ServerSocket ss = new ServerSocket(port);

    // Receber cyphertext

    try {
      Socket s = ss.accept();
      try {
        DataInputStream is = new DataInputStream(s.getInputStream());
        ciphertext = new byte[is.readInt()];
        is.read(ciphertext);

        System.out.println("----------------------------------------------");          System.out.println("Ciphertext recebido (em HEX) ...:\n" 
             +Utils.toHex(ciphertext, ciphertext.length) 
             + " Size: " +ciphertext.length);

      } 
      finally {
        try {
          s.close();
        } catch (Exception e) {

          // nada a considerar... Se quizer trate a excepcao
        } 
      } 
    } 

    finally {
      try {
        ss.close();
      } catch (Exception e) {

        // nada a considerar... Se quizer trate a excepcao
      } 
    }

    // Decifrar com a chave secreta

    System.out.println("Decifrar mensagem recebida ...");

    Cipher cipher = Cipher.getInstance(ciphersuite, provedor);
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
  
    byte[] plainText= new byte[cipher.getOutputSize(ciphertext.length)];
    int ptLength=cipher.update(ciphertext,0, ciphertext.length, plainText,0);
    
    ptLength += cipher.doFinal(plainText, ptLength);
    System.out.println("Plaintext em HEX: "+ Utils.toHex(plainText, ptLength) +
		       " Size: " +ptLength );

    String msgoriginal= new String(plainText);

    System.out.println("----------------------------------------------");      
    System.out.println("MSG Plaintext original: "+ msgoriginal );
    System.out.println("----------------------------------------------");      
    }
  } 
}

