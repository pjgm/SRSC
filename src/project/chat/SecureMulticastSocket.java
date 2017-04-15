package project.chat;

import project.config.GroupConfig;
import project.containers.SecureContainer;
import project.exceptions.CorruptedMessageException;
import project.exceptions.DuplicateMessageException;
import project.parsers.GroupConfigParser;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;


public class SecureMulticastSocket extends MulticastSocket {

    private Cipher cipher;
    private Mac mac;
    private GroupConfig config;
    private Set<ByteBuffer> nonceSet;
    private static final int VERSION = 1;
    private static final int LAYOUT = 1;



    SecureMulticastSocket(int port, String configPath) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException {
        super(port);
        GroupConfigParser parser = new GroupConfigParser(configPath);
        config = parser.parseFile();
        cipher = Cipher.getInstance(config.getCipherSuite());
        mac = Mac.getInstance(config.getMacAlgorithm());
        nonceSet = new HashSet<>();
    }

    @Override
    public void send (DatagramPacket packet) {
        try {

            byte[] input = packet.getData();
            byte[] nonce = generateNonce();

            cipher.init(Cipher.ENCRYPT_MODE, config.getSymmetricKeyValue()); // IV is generated when one is needed
            byte[] cipherText = new byte[cipher.getOutputSize(input.length + nonce.length)];
            int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
            ctLength += cipher.doFinal(nonce, 0 , nonce.length, cipherText, ctLength);

            mac.init(config.getMacKeyValue());
            byte[] macBytes = mac.doFinal(cipherText);

            SecureContainer container = new SecureContainer(VERSION, LAYOUT, ctLength, cipherText, macBytes);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);

            oos.writeObject(container);
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

            SecureContainer container = (SecureContainer) ois.readObject();
            ois.close();

            int ctLength = container.getPayloadSize();
            byte[] cipherText = container.getPayload();

            mac.init(config.getMacKeyValue());
            byte[] macBytes = mac.doFinal(cipherText);

            if (!MessageDigest.isEqual(macBytes, container.getMAC()))
                throw new CorruptedMessageException("Message was corrupted or tampered with");

            if (needsIV())
                cipher.init(Cipher.DECRYPT_MODE, config.getSymmetricKeyValue(), new IvParameterSpec(cipher.getIV()));
            else
                cipher.init(Cipher.DECRYPT_MODE, config.getSymmetricKeyValue());

            byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
            int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
            ptLength += cipher.doFinal(plainText, ptLength);
            byte[] nonce = Arrays.copyOfRange(plainText, ptLength - config.getNonceSize(), ptLength);

            if (nonceSet.contains(ByteBuffer.wrap(nonce)))
                throw new DuplicateMessageException("Duplicate message. Possible replaying attack.");

            nonceSet.add(ByteBuffer.wrap(nonce));

            packet.setData(plainText);

        } catch (GeneralSecurityException | ClassNotFoundException e) {
            e.printStackTrace();
        } catch (DuplicateMessageException | CorruptedMessageException e) {
            System.err.println(e.getMessage());
        }
    }

    private boolean needsIV() {
        return !config.getMode().equals("ECB");
    }

    private byte[] generateNonce() {
        SecureRandom r = new SecureRandom();
        byte [] nonce = new byte[config.getNonceSize()];
        r.nextBytes(nonce);
        return nonce;
    }
}