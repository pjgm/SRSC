package test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;

public class TestingServer {

    public static void main(String args[]) {
        try {
            MulticastSocket socket = new MulticastSocket(9000);
            byte msg[] = "ola teste1233".getBytes();
            DatagramPacket packet = new DatagramPacket(msg, msg.length, InetAddress.getByName("localhost"), 9000);
            socket.send(packet);
            socket.receive(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
