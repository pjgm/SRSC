package labs.EncryptDecrypt.ex1; /**
 * Materiais/Labs para SRSC 16/17, Sem-2
 * Henrique Domingos, 12/3/17
 **/


import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class hjCipherTest {
    public static void main(String args[]) {
        try {
	    // Primeiro vamos gerar a chave
	    // a maneira de obter a chave pode ser variada: 
	    // podemos ter uma numa keystore ja existente ou podemos 
	    // simplesmente gerar uma ou podemos obte-la atraves der
	    // um protocolo seguro de distribuicao de chaves

            KeyGenerator kg = KeyGenerator.getInstance(args[1]);
            Cipher c = Cipher.getInstance(args[2]+"/"+args[3]+"/"+args[4]);

            // ... ou exemplo
	    // KeyGenerator kg = KeyGenerator.getInstance("DESede");
            // Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            Key key = kg.generateKey();
	   
	    // Precisamos tb de um vector de inicializacao
	    // dado o modo de cifra que vamos usar: CBC

            c.init(Cipher.ENCRYPT_MODE, key);
            byte input[] = args[0].getBytes();
            byte encrypted[] = c.doFinal(input);
            byte iv[] = c.getIV();
	   
            System.out.println("Cifrar:");	   
            System.out.println("Ciphertext:");	   
            System.out.println(new String(encrypted));	   

	    // Podemos agora decifrar simetricamente
	    // Importante que o IV seja conhecido para
	    // se poder decifrar. Num caso geral podera ter que
	    // ser transmitido ao destinatario que precisa de
	    // decifrar, juntamente com a mensagem cifrada
	    // Notar que se for preciso passar tb a chave esta
	    // tera que ser passada de forma segura

            System.out.println("Decifrar:");	   
            IvParameterSpec dps = new IvParameterSpec(iv);
            c.init(Cipher.DECRYPT_MODE, key, dps);
            byte output[] = c.doFinal(encrypted);
            System.out.println("Plaintext inicial:");
            System.out.println(new String(output));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

