package project.config;

import javax.crypto.spec.SecretKeySpec;

public class PBECryptoConfig {

    private String algorithm;
    private byte[] salt;
    private int iterationCount;

    public PBECryptoConfig() {

    }


    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public int getIterationCount() {
        return iterationCount;
    }

    public void setIterationCount(int iterationCount) {
        this.iterationCount = iterationCount;
    }
}
