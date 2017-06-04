package project.config;

import javax.crypto.spec.SecretKeySpec;

public class GroupConfig {

    private String symmetricAlgorithm;
    private String mode;
    private String padding;
    private int symmetricKeySize;
    private SecretKeySpec symmetricKeyValue; //change type later
    private String macAlgorithm;
    private int macKeySize;
    private SecretKeySpec macKeyValue; //change type later
    private int nonceSize;
    private SecretKeySpec ephemeralSymmetricKeyValue = null;


    public GroupConfig() {

    }

    public String getCipherSuite() {
        return symmetricAlgorithm + "/" + mode + "/" + padding;
    }

    public String getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }

    public void setSymmetricAlgorithm(String symmetricAlgorithm) {
        this.symmetricAlgorithm = symmetricAlgorithm;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }

    public int getSymmetricKeySize() {
        return symmetricKeySize;
    }

    public void setSymmetricKeySize(int symmetricKeySize) {
        this.symmetricKeySize = symmetricKeySize;
    }

    public SecretKeySpec getSymmetricKeyValue() {
        return symmetricKeyValue;
    }
    public SecretKeySpec getSymmetricEphemeralKeyValue() {
        return ephemeralSymmetricKeyValue;
    }
    public void setSymmetricEphemeralKeyValue(SecretKeySpec k) {
        ephemeralSymmetricKeyValue = k;
    }

    public void setSymmetricKeyValue(SecretKeySpec symmetricKeyValue) {
        this.symmetricKeyValue = symmetricKeyValue;
    }

    public String getMacAlgorithm() {
        return macAlgorithm;
    }

    public void setMacAlgorithm(String macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    public int getMacKeySize() {
        return macKeySize;
    }

    public void setMacKeySize(int macKeySize) {
        this.macKeySize = macKeySize;
    }

    public SecretKeySpec getMacKeyValue() {
        return macKeyValue;
    }

    public void setMacKeyValue(SecretKeySpec macKeyValue) {
        this.macKeyValue = macKeyValue;
    }

    public int getNonceSize() {
        return nonceSize;
    }

    public void setNonceSize(int nonceSize) {
        this.nonceSize = nonceSize;
    }
}
