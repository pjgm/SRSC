package test;


import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.Provider;
import java.security.Security;

public class TestingClient {

    public static void main(String args[]) {
        for (Provider provider: Security.getProviders()) {
            System.out.println(provider.getName());
            for (Provider.Service s: provider.getServices()){
                if (s.getType().equals("Cipher"))
                    System.out.println("\t"+s.getType()+" "+ s.getAlgorithm());
            }
        }

    }
}
