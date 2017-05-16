package project.pbe;

import project.config.PBEConfig;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PBEncryption {

    private Cipher c;
    private Key key;
    private PBEConfig config;
    private byte[] data;
    private byte[] iv;

    public PBEncryption(String password, byte[] data, PBEConfig config) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException {
        this.c = Cipher.getInstance(config.getAlgorithm());
        PBEKeySpec pbeSpec = new PBEKeySpec(password.toCharArray());
        this.config = config;
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(config.getAlgorithm());
        this.key = keyFactory.generateSecret(pbeSpec);
        this.data = data;
        this.iv = null;
    }

    public byte[] encryptFile() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        c.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(config.getSalt(), config.getIterationCount()));
        byte[] out = c.doFinal(data);
        if (c.getIV() != null)
            iv = c.getIV();
        return out;
    }

    public byte[] decryptFile(byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        if (iv != null)
            c.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(config.getSalt(), config.getIterationCount(), new
                    IvParameterSpec(iv)));
        else
            c.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(config.getSalt(), config.getIterationCount()));

        byte[] out = c.doFinal(data);
        return out;
    }

    public byte[] getIv() {
        return iv;
    }
}
