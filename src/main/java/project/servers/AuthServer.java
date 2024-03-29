package project.servers;

import project.config.GroupConfig;
import project.config.PBEConfig;
import project.config.TLSConfig;
import project.containers.AuthContainer;
import project.exceptions.VersionNotAllowedException;
import project.parsers.*;
import project.pbe.PBEncryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.*;

public class AuthServer {

    private String allowedProtocolsArr[] = {"TLSv1.2"};
    private Set<String> allowedProtocols;
    private Map<String, byte[]> authorizedUsers;
    private Map<String, List<String>> accessControl;

    String tlsConfigPath, authUsersPath, accessControlPath, cryptocfgPath;

    public AuthServer(int port, String tlsConfigPath, String authUsersPath, String accessControlPath, String
            cryptocfgPath) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, VersionNotAllowedException, UnrecoverableKeyException, KeyManagementException, InvalidKeySpecException, NoSuchPaddingException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidParameterSpecException {

        //System.setProperty("javax.net.debug", "all"); // For debugging purposes

        allowedProtocols = new HashSet<>();
        allowedProtocols.addAll(Arrays.asList(allowedProtocolsArr));
        ServerSocket listener = createTLSServerSocket(tlsConfigPath, port);
        this.authorizedUsers = loadAuthUsers(authUsersPath);
        this.accessControl = loadAccessControl(accessControlPath);

        this.tlsConfigPath = tlsConfigPath;
        this.authUsersPath = authUsersPath;
        this.accessControlPath = accessControlPath;
        this.cryptocfgPath = cryptocfgPath;

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

            boolean userExists = authorizedUsers.containsKey(container.getUsername());

            if (!userExists) {
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

            //pbEnc = new PBEncryption(password, data, config);
            //byte[] encryptedCrypto = pbEnc.encryptFile();
            //outputStream.writeUTF(Base64.getEncoder().encodeToString(pbEnc.getIv()));
            //outputStream.writeUTF(Base64.getEncoder().encodeToString(encryptedCrypto));

            //Path path = Paths.get(cryptocfgPath + multicastAddress + ".crypto");
            //byte[] data = Files.readAllBytes(path);
            //outputStream.writeUTF(Base64.getEncoder().encodeToString(data));
            outputStream.writeObject(getGroupConfig(multicastAddress));

            outputStream.close();

        }
    }

    Map<String, GroupConfig> configs = new HashMap<>();
    private GroupConfig getGroupConfig(String group) throws IOException, InvalidParameterSpecException, NoSuchAlgorithmException {
        if(configs.containsKey(group)){
            return configs.get(group);
        }else{
            Path path = Paths.get(cryptocfgPath +"/"+ group + ".crypto");
            byte[] data = Files.readAllBytes(path);
            GroupConfigParser groupConfigParser = new GroupConfigParser(data);
            GroupConfig cryptoconf = groupConfigParser.parseFile();
            if(cryptoconf.getDiffieHellmanG()==null || cryptoconf.getDiffieHellmanP()==null)
            {
                DHParameterSpec newSpec = getAlternateDHParams(cryptoconf.getDiffieHellmanSize());
                cryptoconf.setDiffieHellmanG(newSpec.getG());
                cryptoconf.setDiffieHellmanP(newSpec.getP());
                System.out.println("["+group+"] no DH parameters were found. New parameters were generated.");
            }
            configs.put(group, cryptoconf);
            return cryptoconf;
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

        project.cert_validation.TrustManager tm[] = new project.cert_validation.TrustManager[] {new project.cert_validation.TrustManager()};
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tm, null);
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

    public static DHParameterSpec getAlternateDHParams(int size) throws NoSuchAlgorithmException, InvalidParameterSpecException {
        System.out.println("Generating DH parameters...");
        AlgorithmParameterGenerator generator = AlgorithmParameterGenerator.getInstance("DH");
        generator.init(size);
        AlgorithmParameters params = generator.generateParameters();
        System.out.println("Finished generation of DH parameters.");
        return params.getParameterSpec(DHParameterSpec.class);
    }

    public static void main(String args[]) throws Exception{
        new AuthServer(Integer.parseInt(args[0]), args[1], args[2], args[3], args[4]);
    }

}
