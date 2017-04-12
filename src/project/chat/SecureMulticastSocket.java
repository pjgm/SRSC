package project.chat;

import project.config.GroupCryptoConfig;
import project.parsers.GroupCryptoParser;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.NoSuchAlgorithmException;


public class SecureMulticastSocket extends MulticastSocket{

    Cipher cipher;
    GroupCryptoConfig config;

    byte[] ivBytes= new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
    };
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    int ctLength;

    public SecureMulticastSocket(int port, String configPath) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException {
        super(port);

        GroupCryptoParser parser = new GroupCryptoParser(configPath);
        config = parser.parseFile();
        cipher = Cipher.getInstance(config.getCipherSuite());

    }


    // CTR mode working

    @Override
    public void send (DatagramPacket packet) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, config.getSymmetricKeyValue());
            byte input[] = packet.getData();
            byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
            ctLength = cipher.update(input, 0, input.length, cipherText, 0);
            ctLength += cipher.doFinal(cipherText, ctLength);
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
            cipher.init(Cipher.DECRYPT_MODE, config.getSymmetricKeyValue());
            byte cipherText[] = packet.getData();
            byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
            int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
            ptLength += cipher.doFinal(plainText, ptLength);
            packet.setData(plainText);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}