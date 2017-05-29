package project.containers;

import java.io.Serializable;

public class AuthContainer implements Serializable {

    private String username;
    private String address;
    private byte[] nonce;

    public AuthContainer(String username, String address, byte[] nonce) {
        this.username = username;
        this.address = address;
        this.nonce = nonce;
    }

    public String getUsername() {
        return username;
    }

    public String getAddress() {
        return address;
    }

    public byte[] getNonce() {
        return nonce;
    }
}
