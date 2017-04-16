package project.parsers;

import project.config.GroupConfig;

import javax.crypto.spec.SecretKeySpec;
import java.io.*;

public class GroupConfigParser {

    private GroupConfig config;
    BufferedReader br;

    public GroupConfigParser(String path) throws FileNotFoundException {
        br = new BufferedReader(new FileReader(path));
        config = new GroupConfig();
    }

    public GroupConfigParser(byte[] file) {
        config = new GroupConfig();
        InputStream is = new ByteArrayInputStream(file);
        br = new BufferedReader(new InputStreamReader(is));
    }

    public GroupConfig parseFile() throws IOException {
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
            case "noncesize":
                parseNonceSize(value);
        }
    }

    private void parseNonceSize(String value) {
        config.setNonceSize(Integer.parseInt(value)/8);
    }

    private void parseMacKeyValue(String value) {
        byte[] keyBytes = hexStringToByteArray(value);
        if (keyBytes.length != config.getMacKeySize())
            throw new RuntimeException("Declared key length doesn't match lenght of key value in the config file");
        config.setMacKeyValue(new SecretKeySpec(keyBytes, config.getMacAlgorithm()));
    }

    private void parseMacKeySize(String value) {
        config.setMacKeySize(Integer.parseInt(value)/8);
    }

    private void parseMacAlgorithm(String value) {
        config.setMacAlgorithm(value);
    }

    private void parseSymmetricKeyValue(String value) {
        byte[] keyBytes = hexStringToByteArray(value);
        if (keyBytes.length != config.getSymmetricKeySize())
            throw new RuntimeException("Declared key length doesn't match lenght of key value in the config file");
        config.setSymmetricKeyValue(new SecretKeySpec(keyBytes, config.getSymmetricAlgorithm()));
    }

    private void parseSymmetricKeySize(String value) {
        int keySize = Integer.parseInt(value)/8;
        config.setSymmetricKeySize(keySize);
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
