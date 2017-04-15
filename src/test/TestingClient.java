package test;

import project.containers.AuthContainer;

import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class TestingClient {

    public static void main(String args[]) throws IOException, NoSuchAlgorithmException {
        Socket socket = new Socket("localhost", 9000);
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        byte[] nonce = new byte[16];

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] pwHash = md.digest("hashedpw2".getBytes());

        AuthContainer container = new AuthContainer("paulo", "localhost", nonce, pwHash);
        oos.writeObject(container);
        oos.close();
        socket.close();
    }
}
