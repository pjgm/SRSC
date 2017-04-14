package project.container;

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

    int getVersion() {
        return version;
    }

    int getLayout() {
        return layout;
    }

    int getPayloadSize() {
        return payloadSize;
    }
}
