package project.containers;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class SecureContainer implements Serializable {

    private Header header;
    private Payload payload;
    public byte[] signature = null;
    public byte[] certificate = null;
    public ArrayList<byte[]> chain = null;

    public SecureContainer(int version, int layout, int payloadSize, byte[] payload, byte[] mac, byte[] iv) {
        this.header = new Header(version, layout, payloadSize);
        this.payload = new Payload(payload, mac, iv);
    }

    public int getPayloadSize() {
        return header.getPayloadSize();
    }

    public int getVersion() {
        return header.getVersion();
    }

    public int getLayout() {
        return header.getLayout();
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
