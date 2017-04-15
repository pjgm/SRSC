package test;

import project.containers.AuthContainer;
import project.parsers.AccessControlParser;
import project.parsers.AuthParser;

import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

public class TestingServer {

    public static void main(String args[]) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {


        ServerSocket listener = new ServerSocket(9000);
        Socket socket = listener.accept();

        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        AuthContainer container = (AuthContainer) ois.readObject();

        AuthParser parser = new AuthParser("src/test/auth.cfg");
        Map<String, byte[]> users = parser.parseFile();

        AccessControlParser acparser = new AccessControlParser("src/test/accesscontrol.cfg");
        Map<String, List<String>> ac = acparser.parseFile();


        String username = container.getUsername();
        byte[] pwhash = container.getPwHash();

        if (users.containsKey(username) && MessageDigest.isEqual(users.get(username), pwhash) && ac.get("224.0.0.2")
                .contains(username))
            System.out.println("ALLOWED!");
        else
            System.out.println("DENIED!");

        socket.close();
        listener.close();
    }
}
