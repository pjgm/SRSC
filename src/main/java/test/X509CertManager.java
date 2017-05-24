package test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class X509CertManager {

    private static final String KEYSTORETYPE = "JKS";
    private String certPath;

    public X509CertManager(String basePath, String principal) throws Exception {
        if (!principal.equals("client") && !principal.equals("server")) {
            throw new Exception("only client or server allowed");
        }
        this.certPath = basePath + "/" + principal + "Store";

        File f = new File(certPath);
        if (!f.exists()) {
            f.mkdir();
        }
    }

    public KeyStore loadKeyStoreFile(String filename, String password) throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException {

        KeyStore ks = KeyStore.getInstance(KEYSTORETYPE);
        ks.load(new FileInputStream(certPath + "/" + filename), password.toCharArray());
        return ks;
    }

    public void saveKeyStoreFile(KeyStore ks, String filename, String password) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        FileOutputStream fos = new FileOutputStream(certPath + "/" + filename);
        ks.store(fos, password.toCharArray());
        fos.close();
    }

    public KeyStore createEmptyKeyStore(String filename, String password) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, password.toCharArray());
        saveKeyStoreFile(ks, filename, password);
        return ks;
    }

    public KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    public X509Certificate generateSelfSigned(KeyPair keyPair, String signatureAlgorithm, String
            country, String org, String orgUnit, String local, String state) throws
            NoSuchAlgorithmException, OperatorCreationException, IOException, CertificateException {

        Date startDate = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24); // 1 day before
        Date expiryDate = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365); // expires in 1 year

        SecureRandom r = new SecureRandom();
        BigInteger serialNumber = BigInteger.valueOf(Math.abs(r.nextLong())); // serial should be random and positive

        X500Name issuer = new X500Name("C=" + country + ",O=" + org + ",OU=" + orgUnit + ",L=" + local + ",ST=" +
                state);

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, startDate,
                expiryDate, issuer, keyPair.getPublic());

        BasicConstraints basicConstraints = new BasicConstraints(true); // true for CA, false for EndEntity
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
    }

    public void addToKeyStore(String filename, String password, String entryAlias, String entryPassword, X509Certificate
            cert, PrivateKey privateKey) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {

        KeyStore ks = loadKeyStoreFile(filename, password);
        ks.setKeyEntry(entryAlias, privateKey, entryPassword.toCharArray(), new Certificate[]{cert});
        saveKeyStoreFile(ks, filename, password);
    }

    public void addToTrustStore(String filename, String password, X509Certificate cert, String entryAlias) throws
            CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {

        KeyStore ks = loadKeyStoreFile(filename, password);
        ks.setCertificateEntry(entryAlias, cert);
        saveKeyStoreFile(ks, filename, password);
    }

    public static void main(String args[]) throws Exception {
        X509CertManager certManager = new X509CertManager("src/main/java/test", "client");

        KeyStore ks = certManager.loadKeyStoreFile("keystore", "12345678");
        //certManager.createEmptyKeyStore("truststore", "12345678");
        certManager.addToTrustStore("../serverStore/truststore", "12345678", (X509Certificate) ks.getCertificate("entradaprivada"), "clientrsatrustedCert");
        certManager.addToTrustStore("../serverStore/truststore", "12345678", (X509Certificate) ks.getCertificate("dsacert"), "clientdsatrustedCert");
    }
}