package project.parsers;

import javax.crypto.spec.DHParameterSpec;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;

public class DHParser {

    BigInteger p;
    BigInteger g;
    int size;

    public DHParameterSpec parseFile(String path) throws IOException {
        String line;
        BufferedReader br = new BufferedReader(new FileReader(path));
        while ((line = br.readLine()) != null) {
            if (line.startsWith("#") || line.length() == 0)
                continue;
            parseFields(line);
        }
        return new DHParameterSpec(p, g, size-1);
    }

    private void parseFields(String line) {
        String parts[] = line.split(":", 2);
        String field = parts[0].trim().toLowerCase();
        String value = parts[1].trim();

        switch (field) {
            case "p":
                p = new BigInteger(value);
                break;
            case "g":
                g = new BigInteger(value);
                break;
            case "size":
                size = Integer.parseInt(value);
                break;
        }
    }
}
