package project.chat;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.NoSuchAlgorithmException;


public class SecureMulticastSocket extends MulticastSocket{

    Cipher c;
    //Key key;
    byte[]        keyBytes = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

    byte[] ivBytes= new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
    };
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    int ctLength;

    public SecureMulticastSocket(int port) throws IOException {
        super(port);
        KeyGenerator kg = null;
        try {
            //kg = KeyGenerator.getInstance("AES");
            //kg.init(128);
            c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        //key = kg.generateKey();
    }


    // CTR mode working

    @Override
    public void send (DatagramPacket packet) {
        try {
            c.init(Cipher.ENCRYPT_MODE, key);
            byte input[] = packet.getData();
            byte[] cipherText = new byte[c.getOutputSize(input.length)];
            ctLength = c.update(input, 0, input.length, cipherText, 0);
            ctLength += c.doFinal(cipherText, ctLength);
            packet.setData(cipherText);
            super.send(packet);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @Override
    public void receive (DatagramPacket packet) throws IOException {
        super.receive(packet);
        try {
            c.init(Cipher.DECRYPT_MODE, key);
            byte cipherText[] = packet.getData();
            System.out.println("RECEIVE input length: " + cipherText.length);
            System.out.println(ctLength);
            byte[] plainText = new byte[c.getOutputSize(ctLength)];
            int ptLength = c.update(cipherText, 0, ctLength, plainText, 0);
            System.out.println("ptlength before: " + ptLength);
            ptLength += c.doFinal(plainText, ptLength);
            System.out.println("ptlength after: " + ptLength);
            System.out.println(new String(plainText));
            packet.setData(plainText);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}