package EncryptDecrypt.ex2; /**
 * Materiais/Labs para SRSC 16/17, Sem-2
 * Henrique Domingos, 12/3/17
 **/

// KeyRing.java

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;


public class KeyRing {
    /** Inicializacoes para a criptografia simetrica: 
     *  Usar as que quizerem de forma adequada 
    **/

    // public static final String ALGORITHM = "DESede"; // ALgoritmo cripto
    // public static final String ALGORITHM = "Blowfish"; // ALgoritmo cripto
    // etc ... o que tiver sido o alg usado no gerador da chave que ficou
    // no chaveiro ...

    public static final String ALGORITHM = "AES"; // ALgoritmo cripto
    public static final String KEYRING = "keyring"; // Ficheiro do chaveiro

  /**
   * Obtem chave do chaveiro
   * @return :  secret key (gerada para o alg simetrico respetivo)
   * @throws Exception se algo correr mal
   */
  public static SecretKey readSecretKey() throws Exception {

    // Ler a chave secreta
    // System.out.println("Ler a chave do chaveiro...");
    File f=new File(KEYRING);
    long fl= f.length();
    byte[] keyBuffer = new byte[(int)fl];

    InputStream is = new FileInputStream(KEYRING);
    try {
      is.read(keyBuffer);
    } 
    finally {
      try {
        is.close();
      } catch (Exception e) {

        // se quizer tratar a excepcao
      } 
    } 
    // Nota: a chave fica representada no seu formato interno
    // que e um objeto do tipo SecretKey 

    return new SecretKeySpec(keyBuffer, ALGORITHM);
  } 
}

