package test;

import project.config.TLSConfig;
import project.parsers.TLSParser;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class TestingClient {

    public static void main(String args[]) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {

        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        SSLSocket sslSocket = (SSLSocket) factory.createSocket("localhost", 50000);

        TLSConfig tlsConfig = new TLSParser("src/main/java/test/clientStore/tls.config").parseFile();

        System.setProperty("javax.net.ssl.trustStore", tlsConfig.getTruststore());

        sslSocket.setEnabledProtocols(tlsConfig.getProtocols());
        sslSocket.setEnabledCipherSuites(tlsConfig.getCiphersuites());

        System.out.println("Enabled ciphers " + Arrays.asList(sslSocket.getEnabledCipherSuites()));
        System.out.println("test enabled protocols: " + Arrays.asList(sslSocket.getEnabledProtocols()));

        try {
            sslSocket.startHandshake();
        } catch (Exception e) {
            e.printStackTrace();
        }
        printSocketInfo(sslSocket);

    }

    private static void printSocketInfo(SSLSocket s) {

        System.out.println("\n------------------------------------------------------\n");
        System.out.println("Socket class: "+s.getClass());
        System.out.println("   Remote address = " +s.getInetAddress().toString());
        System.out.println("   Remote port = "+s.getPort());
        System.out.println("   Local socket address = " +s.getLocalSocketAddress().toString());
        System.out.println("   Local address = " +s.getLocalAddress().toString());
        System.out.println("   Local port = "+s.getLocalPort());
        System.out.println("   Need client authentication = " +s.getNeedClientAuth());
        System.out.println("   Client mode = " +s.getUseClientMode());
        System.out.println("\n------------------------------------------------------\n");

        System.out.println("   Enabled Protocols = " + Arrays.asList(s.getEnabledProtocols()));
        System.out.println("\n------------------------------------------------------\n");

        System.out.println("   Client Supported Ciphersuites = " +Arrays.asList(s.getSupportedCipherSuites()));
        System.out.println("\n------------------------------------------------------\n");
        System.out.println("   Enabled Ciphersuites = " +Arrays.asList(s.getEnabledCipherSuites()));

        System.out.println("\n------------------------------------------------------\n");

        SSLSession ss = s.getSession();

        System.out.println("   Peer Host: "+ss.getPeerHost());
        System.out.println("   Peer Port: "+ss.getPeerPort());

        System.out.println("   Protocol = "+ss.getProtocol());
        System.out.println("   Cipher suite = "+ss.getCipherSuite());

        System.out.println("   Packet Buffer Size = "+ss.getPacketBufferSize());

        System.out.println("\n------------------------------------------------------\n");


    }
}
