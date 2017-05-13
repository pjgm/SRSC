package TLSCODE;

import java.io.*;
import java.net.*;
import java.security.*;
import javax.net.ssl.*;

public class TLSServer {

    public static void main(String[] args) {
	String ksName = args[0];    // serverkeystore
	char[]  ksPass = args[1].toCharArray();   // password da keystore
	char[]  ctPass = args[2].toCharArray();  // password entry
	int port= Integer.parseInt(args[3]);


        String[] confciphersuites={"TLS_RSA_WITH_AES_256_CBC_SHA256"};
        String[] confprotocols={"TLSv1.2"};

	try {
	    KeyStore ks = KeyStore.getInstance("JKS");
	    ks.load(new FileInputStream(ksName), ksPass);
         KeyManagerFactory kmf = 
	     KeyManagerFactory.getInstance("SunX509");
         kmf.init(ks, ctPass);
         SSLContext sc = SSLContext.getInstance("TLS");
         sc.init(kmf.getKeyManagers(), null, null);
         SSLServerSocketFactory ssf = sc.getServerSocketFactory();
         SSLServerSocket s 
	     = (SSLServerSocket) ssf.createServerSocket(port);

         s.setEnabledProtocols(confprotocols);
	 s.setEnabledCipherSuites(confciphersuites);
     
         printServerSocketInfo(s);


         SSLSocket c = (SSLSocket) s.accept();
         printSocketInfo(c);
         BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
			      c.getOutputStream()));
         BufferedReader r = new BufferedReader(new InputStreamReader(
			     c.getInputStream()));

         // Service from this server ...
         String m = "Welcome !"+
	     " Type in some words, I will reverse them.";
         w.write(m,0,m.length());
         w.newLine();
         w.flush();
         while ((m=r.readLine())!= null) {
	     if (m.equals(".")) break;
	     char[] a = m.toCharArray();
	     int n = a.length;
	     for (int i=0; i<n/2; i++) {
		 char t = a[i];
		 a[i] = a[n-1-i];
		 a[n-i-1] = t;
	     }
	     w.write(a,0,n);
	     w.newLine();
	     w.flush();
         }
         w.close();
         r.close();
         c.close();
         s.close();
	} catch (Exception e) {
	    System.err.println(e.toString());
	}
    }
    private static void printSocketInfo(SSLSocket s) {
	System.out.println("Socket class: "+s.getClass());
	System.out.println("   Remote address = "
			   +s.getInetAddress().toString());
	System.out.println("   Remote port = "+s.getPort());
	System.out.println("   Local socket address = "
			   +s.getLocalSocketAddress().toString());
	System.out.println("   Local address = "
			   +s.getLocalAddress().toString());
	System.out.println("   Local port = "+s.getLocalPort());
	System.out.println("   Need client authentication = "
			   +s.getNeedClientAuth());
	SSLSession ss = s.getSession();
	System.out.println("   Cipher suite = "+ss.getCipherSuite());
	System.out.println("   Protocol = "+ss.getProtocol());
    }
    private static void printServerSocketInfo(SSLServerSocket s) {
	System.out.println("Server socket class: "+s.getClass());
	System.out.println("   Socker address = "
			   +s.getInetAddress().toString());
	System.out.println("   Socker port = "
			   +s.getLocalPort());
	System.out.println("   Need client authentication = "
			   +s.getNeedClientAuth());
	System.out.println("   Want client authentication = "
			   +s.getWantClientAuth());
	System.out.println("   Use client mode = "
			   +s.getUseClientMode());
    } 
}
