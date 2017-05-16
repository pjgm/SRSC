package project.containers;

import java.io.Serializable;

public class AuthContainer implements Serializable {

    private String username;
    private String address;
    private byte[] nonce;
    private byte[] pwHash;

    public AuthContainer(String username, String address, byte[] nonce, byte[] pwHash) {
        this.username = username;
        this.address = address;
        this.nonce = nonce;
        this.pwHash = pwHash;
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

    public byte[] getPwHash() {
        return pwHash;
    }
}
