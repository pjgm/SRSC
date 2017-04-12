package project.parsers;

import project.config.PBECryptoConfig;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class PBECryptoParser {

    private String path;
    private PBECryptoConfig config;

    public PBECryptoParser(String path) {
        this.path = path;
        this.config = new PBECryptoConfig();
    }

    public PBECryptoConfig parseFile() throws IOException {
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
            case "pbe":
                parsePBEAlgorithm(value);
            case "salt":
                parseSalt(value);
            case "ctr":
                parseIterationCount(value);
        }
    }

    private void parseIterationCount(String value) {
        config.setIterationCount(Integer.parseInt(value));
    }

    private void parseSalt(String value) {
        config.setSalt(hexStringToByteArray(value));
    }

    private void parsePBEAlgorithm(String value) {
        config.setAlgorithm(value);
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
