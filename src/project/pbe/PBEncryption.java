package project.pbe;

import project.config.PBEConfig;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PBEncryption {

    private static String CFGPATH = "src/project/cfgfiles/";
    private Cipher c;
    private Key key;
    private PBEConfig config;
    private String file;

    public PBEncryption(String password, String file, PBEConfig config) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException {
        this.c = Cipher.getInstance(config.getAlgorithm());
        PBEKeySpec pbeSpec = new PBEKeySpec(password.toCharArray());
        this.file = file;
        this.config = config;
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(config.getAlgorithm());
        this.key = keyFactory.generateSecret(pbeSpec);
    }

    public void encryptFile() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        c.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(config.getSalt(), config.getIterationCount()));
        byte[] data = Files.readAllBytes(Paths.get(CFGPATH + file + ".crypto"));
        byte[] out = c.doFinal(data);
        FileOutputStream fos = new FileOutputStream(CFGPATH + file);
        fos.write(out);
        fos.close();
    }

    public void decryptFile() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        if (c.getIV() != null) {
            c.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(config.getSalt(), config.getIterationCount(), new IvParameterSpec(c.getIV())));
        }
        else {
            c.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(config.getSalt(), config.getIterationCount()));
        }
        byte[] data = Files.readAllBytes(Paths.get(CFGPATH + file));
        byte[] out = c.doFinal(data);
        FileOutputStream fos = new FileOutputStream(CFGPATH + file + ".crypto");
        fos.write(out);
        fos.close();
    }
}
