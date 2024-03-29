package project.parsers;

import project.config.PBEConfig;

import java.io.*;

public class PBEConfigParser {

    private PBEConfig config;
    private BufferedReader br;

    public PBEConfigParser(String path) throws FileNotFoundException {
        this.config = new PBEConfig();
        this.br = new BufferedReader(new FileReader(path));
    }

    public PBEConfigParser(byte[] file) {
        this.config = new PBEConfig();
        InputStream is = new ByteArrayInputStream(file);
        this.br = new BufferedReader(new InputStreamReader(is));
    }

    public PBEConfig parseFile() throws IOException {
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
                break;
            case "salt":
                parseSalt(value);
                break;
            case "ctr":
                parseIterationCount(value);
                break;
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
