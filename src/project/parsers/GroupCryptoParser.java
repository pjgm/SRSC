package project.parsers;

import project.config.GroupCryptoConfig;

import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class GroupCryptoParser {

    private GroupCryptoConfig config;
    private String path;

    public GroupCryptoParser(String path) {
        this.path = path;
        config = new GroupCryptoConfig();
    }

    public GroupCryptoConfig parseFile() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(path));
        String line;

        while ((line = br.readLine()) != null) {
            if (line.startsWith("#") || line.length() == 0)
                continue;
            parseFields(line);
        }
        return config;
    }

    private void parseFields(String line) {
        String parts[] = line.split(":", 2);
        String field = parts[0].trim().toLowerCase();
        String value = parts[1].trim();

        switch (field) {
            case "ciphersuite":
                parseCipherSuite(value);
                break;
            case "keysize":
                parseSymmetricKeySize(value);
                break;
            case "keyvalue":
                parseSymmetricKeyValue(value);
                break;
            case "mac":
                parseMacAlgorithm(value);
                break;
            case "mackeysize":
                parseMacKeySize(value);
                break;
            case "mackeyvalue":
                parseMacKeyValue(value);
                break;
        }
    }

    private void parseMacKeyValue(String value) {
        System.out.println(value);
        byte[] keyBytes = hexStringToByteArray(value);
        config.setMacKeyValue(new SecretKeySpec(keyBytes, config.getMacAlgorithm()));
    }

    private void parseMacKeySize(String value) {
        config.setMacKeySize(Integer.parseInt(value));
    }

    private void parseMacAlgorithm(String value) {
        config.setMacAlgorithm(value);
    }

    private void parseSymmetricKeyValue(String value) {
        byte[] keyBytes = hexStringToByteArray(value);
        config.setSymmetricKeyValue(new SecretKeySpec(keyBytes, config.getSymmetricAlgorithm()));
    }

    private void parseSymmetricKeySize(String value) {
        int keysize = Integer.parseInt(value);
        config.setSymmetricKeySize(keysize);
    }

    private void parseCipherSuite(String value) {
        String parts[] = value.split("/", 3);
        String symmetricAlgorithm = parts[0];
        String mode = parts[1];
        String padding = parts[2];
        config.setSymmetricAlgorithm(symmetricAlgorithm);
        config.setMode(mode);
        config.setPadding(padding);
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
