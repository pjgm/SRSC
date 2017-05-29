package project.containers;

import java.io.Serializable;

public class AuthContainer implements Serializable {

    private String username;
    private String address;

    public AuthContainer(String username, String address) {
        this.username = username;
        this.address = address;
    }

    public String getUsername() {
        return username;
    }

    public String getAddress() {
        return address;
    }
}
