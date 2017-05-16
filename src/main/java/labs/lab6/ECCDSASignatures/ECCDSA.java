package labs.lab6.ECCDSASignatures;// Seguranca de Sistemas e Redes de Computadores
// 2006/2017, hj@fct.unl.pt

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Geracao e verificacao de assinaturas digitais
 * com ECC DSA
 */
public class ECCDSA {

    public static void main (String[] args) throws Exception {

        byte[] message = "important msg to sign with ECC/DSA".getBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");

        // Sel. a curva ECC que vamos usar: P256
        // Ver debate sobre seguranca de curvas elipticas e tipos de
        // curvas - ongoing research
	ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");


        // Outras curvas existem certifcadas sendo hoje tidas como seguras ...
        // Por ex:
        // ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
        // Ver por ex:
	// https://safecurves.cr.yp.to
	kpg.initialize(ecSpec, new SecureRandom());

        // Gerar par de chaves ECC na curva parameterizada
        KeyPair keyPair= kpg.generateKeyPair();


        // Ok temos tudo para usar nas assinaturas ...

	Signature signature = Signature.getInstance("SHA224/ECDSA", "BC");
	signature.initSign(keyPair.getPrivate(), new SecureRandom());
        signature.update(message);

        byte[]  sigBytes = signature.sign();
        System.out.println("ECDSA signature bytes: " + Utils3.toHex(sigBytes));
        // Verificar - neste caso estamos a obter a chave publica do par mas
	// em geral usamos a chave publica que previamente conhecemos de
	// quem assinou.
	// 
        signature.initVerify(keyPair.getPublic());
        signature.update(message);

        if (signature.verify(sigBytes))
        {
            System.out.println("Assinatura ECDSA validada - reconhecida");
        }
        else
        {
            System.out.println("Assinatura nao reconhecida");
        }
    }
}
