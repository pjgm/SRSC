package project.cert_validation;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TrustManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        checkCertFields(x509Certificates);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        checkCertFields(x509Certificates);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    private void checkCertFields(X509Certificate[] x509Certificates) throws CertificateException {
        for (X509Certificate cert : x509Certificates) {
            cert.checkValidity();
            int version = cert.getVersion();
            String issuerDN = cert.getIssuerDN().toString().toUpperCase();
            if (version != 3 && issuerDN.equals("CN=CA")) {
                throw new CertificateException("Certificate not valid: the version and issuer must be correct " +
                        "for this program to run");
            }
        }
    }
}
