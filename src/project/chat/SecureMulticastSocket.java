package project.chat;

import project.config.GroupCryptoConfig;
import project.parsers.GroupCryptoParser;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;


public class SecureMulticastSocket extends MulticastSocket {

    Cipher cipher;
    GroupCryptoConfig config;

    public SecureMulticastSocket(int port, String configPath) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException {
        super(port);
        GroupCryptoParser parser = new GroupCryptoParser(configPath);
        config = parser.parseFile();
        cipher = Cipher.getInstance(config.getCipherSuite());
    }

    @Override
    public void send (DatagramPacket packet) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, config.getSymmetricKeyValue()); // IV is generated when one is needed
            byte input[] = packet.getData();
            byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
            int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
            ctLength += cipher.doFinal(cipherText, ctLength);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);

            oos.writeInt(ctLength);
            oos.write(cipherText);
            oos.close();

            packet.setData(baos.toByteArray());
            super.send(packet);
        }
        catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void receive (DatagramPacket packet) throws IOException {
        try {
            super.receive(packet);

            ByteArrayInputStream bin = new ByteArrayInputStream(packet.getData());
            ObjectInputStream ois = new ObjectInputStream(bin);

            int ctLength = ois.readInt();
            byte[] cipherText = new byte[ctLength];
            ois.read(cipherText);
            ois.close();

            if (needsIV())
                cipher.init(Cipher.DECRYPT_MODE, config.getSymmetricKeyValue(), new IvParameterSpec(cipher.getIV()));
            else
                cipher.init(Cipher.DECRYPT_MODE, config.getSymmetricKeyValue());

            byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
            int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
            ptLength += cipher.doFinal(plainText, ptLength);
            packet.setData(plainText);
        }
        catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }


    private boolean needsIV() {
        return !config.getMode().equals("ECB");
    }
}