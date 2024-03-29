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
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
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
    private static final byte ENCRYPTED_PAYLOAD = 100;
    private static final byte PLAIN_PAYLOAD = 101;
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
        encryptWithKeyAndSend(packet, ENCRYPTED_PAYLOAD);
    }

    public void sendWithKnownEncryption (DatagramPacket packet) {
        encryptWithKeyAndSend(packet, PLAIN_PAYLOAD);
    }

    private void encryptWithKeyAndSend(DatagramPacket packet, int type){
        try {
            SecretKeySpec key;
            if(type == ENCRYPTED_PAYLOAD){
                key = config.getSymmetricEphemeralKeyValue();
                if(config.getSymmetricEphemeralKeyValue()==null) {
                    //fallback to group key if no ephemeral key was negotiated
                    key = config.getSymmetricKeyValue();
                }else {
                    key = config.getSymmetricEphemeralKeyValue();
                    //System.out.println("----------------used ephemeral key");
                }
            }else{
                key = config.getSymmetricKeyValue();
            }

            byte[] input = packet.getData();
            byte[] nonce = generateNonce();

            byte[] plainText = new byte[input.length + nonce.length];

            System.arraycopy(input, 0, plainText, 0, input.length);
            System.arraycopy(nonce, 0, plainText, input.length, nonce.length);

            cipher.init(Cipher.ENCRYPT_MODE, key); // IV is generated when one is needed

            byte[] cipherText = cipher.doFinal(plainText);

            mac.init(config.getMacKeyValue());
            byte[] macBytes = mac.doFinal(cipherText);

            SecureContainer container = new SecureContainer(VERSION, LAYOUT, input.length, cipherText, macBytes,
                    cipher.getIV());

            if(PLAIN_PAYLOAD==type){
                X509KeyManager km =MChatCliente.getGlobalKeyMngr();
                if(km!=null){
                    String[] certs = km.getClientAliases("RSA", null);
                    if (certs.length>0 && null!=km.getPrivateKey(certs[0])){
                        PrivateKey privateKey = km.getPrivateKey(certs[0]);
                        Signature signature = Signature.getInstance("SHA1withRSA", "BC");
                        //System.out.println("-----------------signed payload");
                        signature.initSign(privateKey);
                        signature.update(cipherText);
                        byte[] sig = signature.sign();
                        container.signature = sig;
                        X509Certificate[] chain = km.getCertificateChain(certs[0]);
                        X509Certificate usedCert = chain[0];
                        /*int i=0;
                        container.chain = new ArrayList<>(chain.length);
                        for(X509Certificate cert : chain){
                            System.out.println(cert.getSubjectX500Principal().getName() +" : ");
                            container.chain.add(cert.getEncoded());
                        }*/
                        container.certificate = usedCert.getEncoded();
                    }
                }
            }


            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.write(type);
            oos.writeObject(container);
            oos.close();

            packet.setData(baos.toByteArray());

            super.send(packet);
        }
        catch (GeneralSecurityException | IOException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
        }

    }
/*
    public void sendNoEncription(DatagramPacket packet) throws IOException {
        byte[] input = packet.getData();
        byte[] nonce = generateNonce();

        byte[] plainText = new byte[input.length + nonce.length];

        System.arraycopy(input, 0, plainText, 0, input.length);
        System.arraycopy(nonce, 0, plainText, input.length, nonce.length);

        //TODO: sign
        SecureContainer container = new SecureContainer(VERSION, LAYOUT, input.length, plainText,null, cipher.getIV());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.write(PLAIN_PAYLOAD);
        oos.writeObject(container);
        oos.close();

        packet.setData(baos.toByteArray());
        super.send(packet);
    }
*/
    @Override
    public void receive (DatagramPacket packet) throws IOException {
        try {
            super.receive(packet);



            ByteArrayInputStream bin = new ByteArrayInputStream(packet.getData());
            ObjectInputStream ois = new ObjectInputStream(bin);
            byte type = ois.readByte();
            SecureContainer container = (SecureContainer) ois.readObject();
            ois.close();

            int version = container.getVersion();
            int layout = container.getLayout();

            if (!ALLOWED_VERSIONS.contains(version))
                throw new VersionNotAllowedException("Version "+ version + "not compatible with your current version");

            if (container.getLayout() != layout)
                throw new IncompatibleLayoutException("Current layout not compatible with received message");

            int ctLength = container.getPayloadSize();

            SecretKeySpec packetKey = config.getSymmetricKeyValue();
            /* treat plain payload */
            if(type == PLAIN_PAYLOAD){
                Signature signature = Signature.getInstance("SHA1withRSA", "BC");

                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                InputStream in = new ByteArrayInputStream(container.certificate);
                X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);

                signature.initVerify(cert.getPublicKey());
                signature.update(container.getPayload());

                if(signature.verify(container.signature)) {
                    System.out.println("--------------------------msg verified!!!!");
                    TrustManager[] tms = MChatCliente.getGlobalTrustMngr();

                    X509Certificate chain[] = {cert};
                    for (TrustManager trustManager: tms) {
                        if (trustManager instanceof X509TrustManager) {
                            X509TrustManager x509TrustManager = (X509TrustManager)trustManager;
                            x509TrustManager.checkClientTrusted(chain,"RSA");
                        }
                    }
                }else{
                    throw new CorruptedMessageException("Message was corrupted or tampered with");
                }

                /*byte[] plainText = Arrays.copyOfRange(container.getPayload(), 0, ctLength);
                byte[] nonce = Arrays.copyOfRange(container.getPayload(), ctLength, container.getPayload().length);

                //TODO: verify signature

                if (nonceSet.contains(ByteBuffer.wrap(nonce)))
                    throw new DuplicateMessageException("Duplicate message. Possible replaying attack.");

                nonceSet.add(ByteBuffer.wrap(nonce));

                packet.setData(plainText);
                return;*/
            }else{
                if(config.getSymmetricEphemeralKeyValue()!=null)
                    packetKey = config.getSymmetricEphemeralKeyValue();
            }


            byte[] cipherText = container.getPayload();

            mac.init(config.getMacKeyValue());
            byte[] macBytes = mac.doFinal(cipherText);

            if (!MessageDigest.isEqual(macBytes, container.getMAC()))
                throw new CorruptedMessageException("Message was corrupted or tampered with");

            if (needsIV())
                cipher.init(Cipher.DECRYPT_MODE, packetKey, new IvParameterSpec(container.getIv()));
            else
                cipher.init(Cipher.DECRYPT_MODE, packetKey);

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