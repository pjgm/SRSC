package test;

import java.io.IOException;
import java.net.*;

public class TestingClient {

    public static void main(String args[]) throws IOException {
        DatagramSocket socket = new DatagramSocket();
        String s = "sup bitches";
        InetAddress addr = InetAddress.getByName("localhost");
        DatagramPacket packet = new DatagramPacket(s.getBytes(), s.length(), addr, 8888);
        socket.send(packet);
    }
}
