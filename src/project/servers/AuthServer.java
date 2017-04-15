package project.servers;

import project.config.PBEConfig;
import project.containers.AuthContainer;
import project.exceptions.AccessControlException;
import project.exceptions.AuthenticationException;
import project.parsers.AccessControlParser;
import project.parsers.AuthParser;
import project.parsers.PBEConfigParser;
import project.pbe.PBEncryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class AuthServer {

    public static void main(String args[]) throws IOException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, AuthenticationException, AccessControlException {

        int port = Integer.parseInt(args[0]);
        ServerSocket listener = new ServerSocket(port);

        String authcfgPath = args[1];
        AuthParser authParser = new AuthParser(authcfgPath);
        Map<String, byte[]> users = authParser.parseFile();

        String accesscontrolcfgPath = args[2];
        AccessControlParser acparser = new AccessControlParser(accesscontrolcfgPath);
        Map<String, List<String>> ac = acparser.parseFile();

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

            PBEConfigParser pbeConfigParser = new PBEConfigParser("src/project/cryptocfgfiles/" + multicastAddress + ".pbe");
            PBEConfig config = pbeConfigParser.parseFile();
            String password = Base64.getEncoder().encodeToString(users.get(username));
            PBEncryption pbEnc = new PBEncryption(password, encryptedContainer, config);

            byte[] containerBytes = null;

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

            boolean userExists = users.containsKey(container.getUsername());
            boolean isPasswordCorrect = MessageDigest.isEqual(users.get(container.getUsername()), container.getPwHash());

            if (!userExists || !isPasswordCorrect) {
                outputStream.writeInt(1);
                outputStream.close();
                continue;
            }

            boolean isAllowed = ac.get(container.getAddress()).contains(container.getUsername());

            if (!isAllowed) {
                outputStream.writeInt(2);
                outputStream.close();
                continue;
            }

            outputStream.writeInt(3);

            Path path = Paths.get("src/project/cryptocfgfiles/" + multicastAddress + ".crypto");
            byte[] data = Files.readAllBytes(path);

            pbEnc = new PBEncryption(Base64.getEncoder().encodeToString(container.getPwHash()), data, config);
            byte[] encryptedCrypto = pbEnc.encryptFile();

            outputStream.writeUTF(Base64.getEncoder().encodeToString(pbEnc.getIv()));
            outputStream.writeUTF(Base64.getEncoder().encodeToString(encryptedCrypto));

            outputStream.close();

        }


    }

}
