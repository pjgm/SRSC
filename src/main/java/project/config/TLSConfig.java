package project.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class TLSConfig {

    private String ciphersuites[], versions[];
    private KeyStore privateKeyStore;
    private char keystorepw[];
    private String mode, truststore;

    public TLSConfig() {
    }

    public String[] getVersions() {
        return versions;
    }

    public void setVersion(String versions) {
        this.versions = versions.split(" ");
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String[] getCiphersuites() {
        return ciphersuites;
    }

    public void setCiphersuite(String ciphersuites) {
        this.ciphersuites = ciphersuites.split(" ");
    }

    public KeyStore getPrivkeystore() {
        return privateKeyStore;
    }

    public void setPrivkeystore(String path) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        this.privateKeyStore = KeyStore.getInstance("JKS");
        privateKeyStore.load(new FileInputStream(path), keystorepw);
    }

    public String getTruststore() {
        return truststore;
    }

    public void setTruststore(String truststore) {
        this.truststore = truststore;
    }

    public char[] getKeystorepw() {
        return keystorepw;
    }

    public void setKeystorepw(String keystorepw) {
        this.keystorepw = keystorepw.toCharArray();
    }
}
