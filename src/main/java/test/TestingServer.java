package test;

import project.config.TLSConfig;
import project.parsers.TLSParser;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class TestingServer {

    public static void main(String args[]) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, NoSuchProviderException {

        int port = 50000; // Ports below 1024 are called Privileged Ports and must be run as root

        String allowedProtocolsArr[] = {"TLSv1.2"};
        Set<String> allowedProtocols = new HashSet<>();
        allowedProtocols.addAll(Arrays.asList(allowedProtocolsArr));

        TLSConfig tlsConfig = new TLSParser("src/main/java/test/serverStore/tls.config").parseFile();

        System.setProperty("javax.net.ssl.trustStore", tlsConfig.getTruststore());

        for (String v : tlsConfig.getProtocols()) {
            if (!allowedProtocols.contains(v)) {
                System.err.println("Bad config: " + v + " is not an allowed protocol");
            }
        }

        printTLSConfig(tlsConfig);

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

        System.out.println("Enabled ciphers: " + Arrays.asList(serverSocket.getEnabledCipherSuites()));

        SSLSocket sslSocket = (SSLSocket) serverSocket.accept();
        printSocketInfo(sslSocket);
    }

    private static void printTLSConfig(TLSConfig tlsConfig) {
        System.out.println("Version: " + Arrays.asList(tlsConfig.getProtocols()));
        System.out.println("Mode: " + tlsConfig.getMode());
        System.out.println("priv keystore pw: " + new String(tlsConfig.getKeystorepw()));
        System.out.println("priv keystore: " + tlsConfig.getPrivkeystore());
        System.out.println("trust store: " + tlsConfig.getTruststore());
        System.out.println("ciphersuites: " + Arrays.asList(tlsConfig.getCiphersuites()));
    }

    private static void printSocketInfo(SSLSocket s) {
        System.out.println("Socket class: "+s.getClass());
        System.out.println("   Remote address: " + s.getInetAddress().toString());
        System.out.println("   Remote port: "+ s.getPort());
        System.out.println("   Local socket address: " + s.getLocalSocketAddress().toString());
        System.out.println("   Local address: " + s.getLocalAddress().toString());
        System.out.println("   Local port: " + s.getLocalPort());
        System.out.println("   Need client authentication: " + s.getNeedClientAuth());

        SSLSession ss = s.getSession();
        System.out.println("   Cipher suite: " + ss.getCipherSuite());
        System.out.println("   Protocol: "+ss.getProtocol());
    }
}
