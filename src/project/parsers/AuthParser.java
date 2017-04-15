package project.parsers;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class AuthParser {

    private Map<String, byte[]> users;
    private String path;

    public AuthParser(String path) {
        this.users = new HashMap<>();
        this.path = path;
    }

    public Map<String, byte[]> parseFile() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(path));
        String line;

        while ((line = br.readLine()) != null) {
            if (line.startsWith("#") || line.length() == 0)
                continue;
            parseFields(line);
        }
        return users;
    }

    private void parseFields(String line) {
        String parts[] = line.split(":", 2);
        String username = parts[0].trim().toLowerCase();
        String pwhash = parts[1].trim();
        users.put(username, Base64.getDecoder().decode(pwhash));
    }
}
