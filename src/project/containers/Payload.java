package project.containers;

import java.io.Serializable;

class Payload implements Serializable {

    private byte[] data;
    private byte[] mac;
    private byte[] iv;

    Payload(byte[] data, byte[] mac, byte[] iv) {
        this.data = data;
        this.mac = mac;
        this.iv = iv;
    }

    byte[] getData() {
        return data;
    }

    byte[] getMAC() {
        return mac;
    }

    byte[] getIv() {
        return iv;
    }
}
