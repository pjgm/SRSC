package TLSCODE;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.*;
import javax.net.SocketFactory;
import javax.net.ssl.*;

public class TLSTest
{
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: TLSTest host port");
            return;
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);

        SocketFactory factory = SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);

        socket.startHandshake();

        Certificate[] certs = socket.getSession().getPeerCertificates();

        System.out.println("Certs retrieved: " + certs.length);
        for (Certificate cert : certs) {
            System.out.println("Certificate is: " + cert);
            if(cert instanceof X509Certificate) {
                try {
                    ( (X509Certificate) cert).checkValidity();
                    System.out.println("Certificate is active for current date");
                } catch(CertificateExpiredException cee) {
                    System.out.println("Certificate is expired");
                }
            }
        }
    }
}