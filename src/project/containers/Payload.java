package project.containers;

import java.io.Serializable;

class Payload implements Serializable {

    private byte[] data;
    private byte[] mac;

    Payload(byte[] data, byte[] mac) {
        this.data = data;
        this.mac = mac;
    }

    byte[] getData() {
        return data;
    }

    byte[] getMAC() {
        return mac;
    }
}
