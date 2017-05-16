package project.parsers;

import project.config.TLSConfig;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class TLSParser {

    private TLSConfig tlsConfig;
    private BufferedReader br;

    public TLSParser(String path) throws FileNotFoundException {
        br = new BufferedReader(new FileReader(path));
        tlsConfig = new TLSConfig();
    }

    public TLSConfig parseFile() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        String line;

        while ((line = br.readLine()) != null) {
            if (line.startsWith("#") || line.length() == 0)
                continue;
            parseFields(line);
        }
        return tlsConfig;
    }

    private void parseFields(String line) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        String parts[] = line.split(":", 2);
        String field = parts[0].trim().toLowerCase();
        String value = parts[1].trim();

        switch (field) {
            case "tls":
                parseVersion(value);
                break;
            case "aut":
                parseMode(value);
                break;
            case "ciphersuites":
                parseCiphersuites(value);
                break;
            case "privkeystore_password":
                parseKeyStorePw(value);
                break;
            case "privkeystore":
                parsePrivKeyStore(value);
                break;
            case "truststore":
                parseTrustStore(value);
        }
    }

    private void parseKeyStorePw(String password) {
        tlsConfig.setKeystorepw(password);
    }

    private void parseTrustStore(String path) {
        tlsConfig.setTruststore(path);
    }

    private void parsePrivKeyStore(String path) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        tlsConfig.setPrivkeystore(path);
    }

    private void parseCiphersuites(String ciphersuites) {
        tlsConfig.setCiphersuite(ciphersuites);
    }

    private void parseMode(String mode) {
        tlsConfig.setMode(mode);
    }

    private void parseVersion(String version) {
        tlsConfig.setVersion(version);
    }
}
