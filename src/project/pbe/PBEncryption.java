package project.pbe;

import project.config.PBEConfig;

import javax.crypto.*;
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

    private PBEKeySpec pbeSpec;
    private SecretKeyFactory keyFactory;
    private Key key;
    private PBEConfig config;
    private String path;

    public PBEncryption(String password, String path, PBEConfig config) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.pbeSpec = new PBEKeySpec(password.toCharArray());
        this.path = path;
        this.config = config;
        this.keyFactory = SecretKeyFactory.getInstance(config.getAlgorithm());
        this.key = keyFactory.generateSecret(pbeSpec);
    }

    public void encryptFile() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cEnc = Cipher.getInstance(config.getAlgorithm());
        cEnc.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(config.getSalt(), config.getIterationCount()));
        byte[] data = Files.readAllBytes(Paths.get(path));
        byte[] out = cEnc.doFinal(data);
        FileOutputStream fos = new FileOutputStream("src/project/cfgfiles/test");
        fos.write(out);
        fos.close();
    }

    public void decryptFile() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cEnc = Cipher.getInstance(config.getAlgorithm());
        cEnc.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(config.getSalt(), config.getIterationCount()));
        byte[] data = Files.readAllBytes(Paths.get(path));
        byte[] out = cEnc.doFinal(data);
        FileOutputStream fos = new FileOutputStream("src/project/cfgfiles/test.crypto");
        fos.write(out);
        fos.close();
    }
}
