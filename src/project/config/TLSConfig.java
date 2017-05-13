package project.config;

public class TLSConfig {

    private String version, mode, ciphersuite, privkeystore, truststore;

    public TLSConfig() {
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getCiphersuite() {
        return ciphersuite;
    }

    public void setCiphersuite(String ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public String getPrivkeystore() {
        return privkeystore;
    }

    public void setPrivkeystore(String privkeystore) {
        this.privkeystore = privkeystore;
    }

    public String getTruststore() {
        return truststore;
    }

    public void setTruststore(String truststore) {
        this.truststore = truststore;
    }
}
