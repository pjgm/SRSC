package project.containers;

import java.io.Serializable;

class Header implements Serializable {

    private int version;
    private int layout;
    private int payloadSize;

    Header(int version, int layout, int payloadSize) {
        this.version = version;
        this.layout = layout;
        this.payloadSize = payloadSize;
    }

    int getPayloadSize() {
        return payloadSize;
    }
}
