package labs.EncryptDecrypt.ex1; /**
 * Materiais/Labs para SRSC 16/17, Sem-2
 * Henrique Domingos, 12/3/17
 **/

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

// Classe para cifrar uma mensagem (passada como parametro)
// Mensagem cifrada sera depositada num ficheiro chamado ciphertext

public class hjEncryptMessage {
    public static void main(String args[]) {
        try {

            // Vamos gerar uma chave para um algoritmo criptografico simetrico
            // para cifrar depois a mensagem .... 

            KeyGenerator kg = KeyGenerator.getInstance("DES"); // Vamos usar DES
            kg.init(new SecureRandom());  // Secure Random Seed para gerar a chave
            SecretKey key = kg.generateKey(); // Key Generation para o Alg. DES
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
	    Class spec = Class.forName("javax.crypto.spec.DESKeySpec");

	    DESKeySpec ks = (DESKeySpec) skf.getKeySpec(key, spec);
            ObjectOutputStream oos = new ObjectOutputStream(
                        new FileOutputStream("keyring"));

            oos.writeObject(ks.getKey()); // keyfile: ficheiro usado para guardar
                                          // a chave gerada e que vai ser usada

            // Vamos agora cifrar a mensagem dada como argumento
            // ... vamso cifrar ocm DES, modo CFB8 e sem Padding...
            // O ficheiro cifrado sera depois escrito no ficheiro ciphertext

            Cipher c = Cipher.getInstance("DES/CFB8/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key);
            CipherOutputStream cos = new CipherOutputStream(
                        new FileOutputStream("ciphertext"), c);
            PrintWriter pw = new PrintWriter(
                        new OutputStreamWriter(cos));

            pw.println(args[0]); // Mensagem que vamos cifrar ....
            pw.close();
            oos.writeObject(c.getIV()); // Vetor de inicialização para a cifra
                                        // ficara tb no chaveiro com a chave
            oos.close();
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}

