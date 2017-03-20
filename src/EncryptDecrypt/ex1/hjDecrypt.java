package EncryptDecrypt.ex1; /**
 * Materiais/Labs para SRSC 16/17, Sem-2
 * Henrique Domingos, 12/3/17
 **/

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class hjDecrypt {
    public static void main(String args[]) {
        try {
            ObjectInputStream ois = new ObjectInputStream(
                        new FileInputStream("keyring"));
	    // Supostamente o ficheiro que tem a chave e o IV

            DESKeySpec ks = new DESKeySpec((byte[]) ois.readObject());
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            SecretKey key = skf.generateSecret(ks);

            // Ok, tirámos a chave do chaveiro ...
            // Vamos agora decifrar o ficheiro ciphertext

            Cipher c = Cipher.getInstance("DES/CFB8/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, 
                   new IvParameterSpec((byte[]) ois.readObject()));

            CipherInputStream cis = new CipherInputStream(
                        new FileInputStream("ciphertext"), c);

            BufferedReader br = new BufferedReader(
                        new InputStreamReader(cis));
            System.out.println("------------------------:");
            System.out.println("Conteudo cifrado era ...:");
            System.out.println("------------------------:");
            System.out.println(br.readLine());
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}

