package project.container;

import java.io.Serializable;

class Payload implements Serializable {

    private byte[] data;
    private byte[] mac;
    private byte[] nonce;

    Payload(byte[] data, byte[] mac, byte[] nonce) {
        this.data = data;
        this.mac = mac;
        this.nonce = nonce;
    }

    byte[] getData() {
        return data;
    }

    byte[] getMAC() {
        return mac;
    }

    byte[] getNonce() {
        return nonce;
    }
}
