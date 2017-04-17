package project.chat;

import project.config.GroupConfig;
import project.containers.SecureContainer;
import project.exceptions.CorruptedMessageException;
import project.exceptions.DuplicateMessageException;
import project.exceptions.IncompatibleLayoutException;
import project.exceptions.VersionNotAllowedException;

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
    private Set<Integer> ALLOWED_VERSIONS;

    SecureMulticastSocket(int port, GroupConfig config) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException {
        super(port);
        this.config = config;
        cipher = Cipher.getInstance(config.getCipherSuite());
        mac = Mac.getInstance(config.getMacAlgorithm());
        nonceSet = new HashSet<>();
        ALLOWED_VERSIONS = new HashSet<>();
        ALLOWED_VERSIONS.add(1);
    }

    @Override
    public void send (DatagramPacket packet) {
        try {

            byte[] input = packet.getData();
            byte[] nonce = generateNonce();

            byte[] plainText = new byte[input.length + nonce.length];

            System.arraycopy(input, 0, plainText, 0, input.length);
            System.arraycopy(nonce, 0, plainText, input.length, nonce.length);


            cipher.init(Cipher.ENCRYPT_MODE, config.getSymmetricKeyValue()); // IV is generated when one is needed

            byte[] cipherText = cipher.doFinal(plainText);

            mac.init(config.getMacKeyValue());
            byte[] macBytes = mac.doFinal(cipherText);

            SecureContainer container = new SecureContainer(VERSION, LAYOUT, input.length, cipherText, macBytes,
                    cipher.getIV());

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

            int version = container.getVersion();
            int layout = container.getLayout();

            if (!ALLOWED_VERSIONS.contains(version))
                throw new VersionNotAllowedException("Version "+ version + "not compatible with your current version");

            if (container.getLayout() != layout)
                throw new IncompatibleLayoutException("Current layout not compatible with received message");

            int ctLength = container.getPayloadSize();
            byte[] cipherText = container.getPayload();

            mac.init(config.getMacKeyValue());
            byte[] macBytes = mac.doFinal(cipherText);

            if (!MessageDigest.isEqual(macBytes, container.getMAC()))
                throw new CorruptedMessageException("Message was corrupted or tampered with");

            if (needsIV())
                cipher.init(Cipher.DECRYPT_MODE, config.getSymmetricKeyValue(), new IvParameterSpec(container.getIv()));
            else
                cipher.init(Cipher.DECRYPT_MODE, config.getSymmetricKeyValue());

            byte[] combinedPlainText = cipher.doFinal(cipherText);

            byte[] plainText = Arrays.copyOfRange(combinedPlainText, 0, ctLength);
            byte[] nonce = Arrays.copyOfRange(combinedPlainText, ctLength, combinedPlainText.length);

            if (nonceSet.contains(ByteBuffer.wrap(nonce)))
                throw new DuplicateMessageException("Duplicate message. Possible replaying attack.");

            nonceSet.add(ByteBuffer.wrap(nonce));

            packet.setData(plainText);

        } catch (GeneralSecurityException | ClassNotFoundException e) {
            e.printStackTrace();
        } catch (DuplicateMessageException | CorruptedMessageException | VersionNotAllowedException | IncompatibleLayoutException e) {
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