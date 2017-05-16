package project.parsers;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class AccessControlParser {

    private Map<String, List<String>> aclist;
    private String path;

    public AccessControlParser(String path) {
        this.aclist = new HashMap<>();
        this.path = path;
    }

    public Map<String, List<String>> parseFile() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(path));
        String line;

        while ((line = br.readLine()) != null) {
            if (line.startsWith("#") || line.length() == 0)
                continue;
            parseFields(line);
        }
        return aclist;
    }

    private void parseFields(String line) {
        List<String> userList = new LinkedList<>();
        String[] parts = line.split(":", 2);
        String group = parts[0].trim();
        String[] users = parts[1].split(";");
        for (String user : users) {
            userList.add(user.trim());
        }
        aclist.put(group, userList);
    }
}
