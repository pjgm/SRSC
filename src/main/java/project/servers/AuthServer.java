package project.servers;

import project.config.PBEConfig;
import project.config.TLSConfig;
import project.containers.AuthContainer;
import project.exceptions.AccessControlException;
import project.exceptions.AuthenticationException;
import project.exceptions.VersionNotAllowedException;
import project.parsers.AccessControlParser;
import project.parsers.AuthParser;
import project.parsers.PBEConfigParser;
import project.parsers.TLSParser;
import project.pbe.PBEncryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class AuthServer {

    String allowedProtocolsArr[] = {"TLSv1.2"};
    Set<String> allowedProtocols;
    Map<String, byte[]> authorizedUsers;
    Map<String, List<String>> accessControl;
    Set<ByteBuffer> nonceSet;

    public AuthServer(int port, String tlsConfigPath, String authUsersPath, String accessControlPath, String
            cryptocfgPath) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, VersionNotAllowedException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException, NoSuchPaddingException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {

        allowedProtocols = new HashSet<>();
        nonceSet = new HashSet<>();
        allowedProtocols.addAll(Arrays.asList(allowedProtocolsArr));
        ServerSocket listener = createTLSServerSocket(tlsConfigPath, port);
        this.authorizedUsers = loadAuthUsers(authUsersPath);
        this.accessControl = loadAccessControl(accessControlPath);

        while (true) {
            Socket socket = listener.accept();

            ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());

            int length = inputStream.readInt();
            String username = inputStream.readUTF();
            String multicastAddress = inputStream.readUTF();
            String encodedIV = inputStream.readUTF();
            byte[] encryptedContainer = new byte[length];
            inputStream.read(encryptedContainer);

            PBEConfigParser pbeConfigParser = new PBEConfigParser(cryptocfgPath + multicastAddress + ".pbe");
            PBEConfig config = pbeConfigParser.parseFile();
            String password = Base64.getEncoder().encodeToString(authorizedUsers.get(username));
            PBEncryption pbEnc = new PBEncryption(password, encryptedContainer, config);

            byte[] containerBytes;

            try {
                containerBytes = pbEnc.decryptFile(Base64.getDecoder().decode(encodedIV));
            } catch (GeneralSecurityException e) {
                outputStream.writeInt(1);
                outputStream.close();
                continue;
            }

            ByteArrayInputStream bis = new ByteArrayInputStream(containerBytes);
            ObjectInput oi =  new ObjectInputStream(bis);

            AuthContainer container = (AuthContainer) oi.readObject();

            if (nonceSet.contains(ByteBuffer.wrap(container.getNonce()))) {
                System.err.println("Possible replaying attack. Ignoring message");
                continue;
            }

            boolean userExists = authorizedUsers.containsKey(container.getUsername());
            boolean isPasswordCorrect = MessageDigest.isEqual(authorizedUsers.get(container.getUsername()), container.getPwHash());

            if (!userExists || !isPasswordCorrect) {
                outputStream.writeInt(1);
                outputStream.close();
                continue;
            }

            boolean isAllowed = accessControl.get(container.getAddress()).contains(container.getUsername());

            if (!isAllowed) {
                outputStream.writeInt(2);
                outputStream.close();
                continue;
            }

            outputStream.writeInt(3);

            Path path = Paths.get(cryptocfgPath + multicastAddress + ".crypto");
            byte[] data = Files.readAllBytes(path);

            pbEnc = new PBEncryption(Base64.getEncoder().encodeToString(container.getPwHash()), data, config);
            byte[] encryptedCrypto = pbEnc.encryptFile();

            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] nonceHash = md.digest(container.getNonce());

            outputStream.writeUTF(Base64.getEncoder().encodeToString(pbEnc.getIv()));
            outputStream.writeUTF(Base64.getEncoder().encodeToString(encryptedCrypto));
            outputStream.writeUTF(Base64.getEncoder().encodeToString(nonceHash));

            outputStream.close();

        }
    }

    private Map<String, byte[]> loadAuthUsers(String authUsersPath) throws IOException {
        AuthParser authParser = new AuthParser(authUsersPath);
        return authParser.parseFile();
    }


    private Map<String,List<String>> loadAccessControl(String accessControlPath) throws IOException {
        AccessControlParser acparser = new AccessControlParser(accessControlPath);
        return acparser.parseFile();
    }

    private ServerSocket createTLSServerSocket(String tlsConfigPath, int port) throws IOException,
            CertificateException, NoSuchAlgorithmException, KeyStoreException, VersionNotAllowedException, UnrecoverableKeyException, KeyManagementException {

        TLSConfig tlsConfig = new TLSParser(tlsConfigPath).parseFile();
        System.setProperty("javax.net.ssl.trustStore", tlsConfig.getTruststore());

        for (String v : tlsConfig.getProtocols()) {
            if (!allowedProtocols.contains(v)) {
                throw new VersionNotAllowedException("Bad config: " + v + " is not an allowed protocol");
            }
        }

        KeyStore keystore = tlsConfig.getPrivkeystore();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keystore, tlsConfig.getKeystorepw());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);
        SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) socketFactory.createServerSocket(port);

        serverSocket.setEnabledProtocols(tlsConfig.getProtocols());
        serverSocket.setEnabledCipherSuites(tlsConfig.getCiphersuites());

        if (tlsConfig.getMode().equals("CLIENTE-SERVIDOR")) {
            serverSocket.setNeedClientAuth(true);
        } else if (tlsConfig.getMode().equals("CLIENTE")) {
            serverSocket.setUseClientMode(true);
        }
        
        return serverSocket;
    }

    public static void main(String args[]) throws NoSuchPaddingException, InvalidKeySpecException, ClassNotFoundException, NoSuchAlgorithmException, KeyManagementException, CertificateException, UnrecoverableKeyException, BadPaddingException, VersionNotAllowedException, InvalidAlgorithmParameterException, KeyStoreException, IOException, IllegalBlockSizeException, InvalidKeyException {
        new AuthServer(Integer.parseInt(args[0]), args[1], args[2], args[3], args[4]);
    }

}
