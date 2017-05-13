package project.parsers;

import project.config.TLSConfig;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class TLSParser {

    private TLSConfig tlsConfig;
    private BufferedReader br;

    public TLSParser(String path) throws FileNotFoundException {
        br = new BufferedReader(new FileReader(path));
        tlsConfig = new TLSConfig();
    }

    public TLSConfig parseFile() throws IOException {
        String line;

        while ((line = br.readLine()) != null) {
            if (line.startsWith("#") || line.length() == 0)
                continue;
            parseFields(line);
        }
        return tlsConfig;
    }

    private void parseFields(String line) {
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
                parseCiphersuite(value);
                break;
            case "privkeystore":
                parsePrivKeyStore(value);
                break;
            case "truststore":
                parseTrustStore(value);
        }
    }

    private void parseTrustStore(String path) {
        tlsConfig.setTruststore(path);
    }

    private void parsePrivKeyStore(String path) {
        tlsConfig.setPrivkeystore(path);
    }

    private void parseCiphersuite(String ciphersuite) {
        tlsConfig.setCiphersuite(ciphersuite);
    }

    private void parseMode(String mode) {
        tlsConfig.setMode(mode);
    }

    private void parseVersion(String version) {
        tlsConfig.setVersion(version);
    }
}
