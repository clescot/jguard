package net.sf.jguard.ext.authentication.loginmodules;

import net.sf.jguard.core.authentication.callbacks.CertificatesCallback;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Date;
import java.util.Set;

public class CertificatesCallbackTest {


    @Test
    public void testClearCertificates() {
        CertificatesCallback callback = new CertificatesCallback();
        X509Certificate certificate = new X509Certificate() {

            @Override
            public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public int getVersion() {
                return 0;  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public BigInteger getSerialNumber() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public Principal getIssuerDN() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public Principal getSubjectDN() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public Date getNotBefore() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public Date getNotAfter() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public byte[] getTBSCertificate() throws CertificateEncodingException {
                return new byte[0];  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public byte[] getSignature() {
                return new byte[0];  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public String getSigAlgName() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public String getSigAlgOID() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public byte[] getSigAlgParams() {
                return new byte[0];  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public boolean[] getIssuerUniqueID() {
                return new boolean[0];  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public boolean[] getSubjectUniqueID() {
                return new boolean[0];  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public boolean[] getKeyUsage() {
                return new boolean[0];  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public int getBasicConstraints() {
                return 0;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public boolean hasUnsupportedCriticalExtension() {
                return false;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public Set<String> getCriticalExtensionOIDs() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public Set<String> getNonCriticalExtensionOIDs() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public byte[] getExtensionValue(String oid) {
                return new byte[0];  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public byte[] getEncoded() throws CertificateEncodingException {
                return new byte[0];  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public String toString() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            @Override
            public PublicKey getPublicKey() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }
        };
        X509Certificate[] certificates = new X509Certificate[]{certificate};
        callback.setCertificates(certificates);
        callback.clearCertificates();
        Assert.assertTrue(certificates != callback.getCertificates());
        Assert.assertTrue(callback.getCertificates() != null);
        Assert.assertTrue(Arrays.asList(callback.getCertificates()).isEmpty());
    }
}
