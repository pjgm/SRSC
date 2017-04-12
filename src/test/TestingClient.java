package test;


import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;

public class TestingClient {

    public static void main(String args[]) {
        try {
            MulticastSocket socket = new MulticastSocket(9000);
            byte buffer[] = new byte[1000];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, InetAddress.getByName("localhost"),
                    9000);
            socket.receive(packet);
            buffer = packet.getData();
            System.out.println(new String(buffer, 0, packet.getLength()));
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
