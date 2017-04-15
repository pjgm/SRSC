package project.containers;

import java.io.Serializable;

public class SecureContainer implements Serializable {

    private Header header;
    private Payload payload;

    public SecureContainer(int version, int layout, int payloadSize, byte[] payload, byte[] mac, byte[] iv) {
        this.header = new Header(version, layout, payloadSize);
        this.payload = new Payload(payload, mac, iv);
    }

    public int getPayloadSize() {
        return header.getPayloadSize();
    }

    public byte[] getPayload() {
        return payload.getData();
    }

    public byte[] getMAC() {
        return payload.getMAC();
    }

    public byte[] getIv() {
        return payload.getIv();
    }

}
