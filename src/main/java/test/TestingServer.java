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

        String allowedCipherSuitesArr[] = {"TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"};
        Set<String> allowedCipherSuites = new HashSet<>();
        allowedCipherSuites.addAll(Arrays.asList(allowedCipherSuitesArr));

        String allowedProtocolsArr[] = {"TLSv1.2"};
        Set<String> allowedProtocols = new HashSet<>();
        allowedProtocols.addAll(Arrays.asList(allowedProtocolsArr));

        TLSConfig tlsConfig = new TLSParser("src/test/tls.config").parseFile();

        //check if config is allowed, if one ciphersuite doesnt exist exit the prog or ignore?
        for (String c : tlsConfig.getCiphersuites()) {
            if (!allowedCipherSuites.contains(c)) {
                System.err.println("Bad config: " + c + " is not an allowed ciphersuite");
                System.exit(1);
            }
        }

        // One or multiple versions in cfg?
        for (String v : tlsConfig.getVersions()) {
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


        serverSocket.setEnabledProtocols(tlsConfig.getVersions());
        serverSocket.setEnabledCipherSuites(tlsConfig.getCiphersuites());

        System.out.println("Enabled ciphers: " + Arrays.asList(serverSocket.getEnabledCipherSuites()));

        SSLSocket sslSocket = (SSLSocket) serverSocket.accept();
        printSocketInfo(sslSocket);
    }

    private static void printTLSConfig(TLSConfig tlsConfig) {
        System.out.println("Version: " + Arrays.asList(tlsConfig.getVersions()));
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
