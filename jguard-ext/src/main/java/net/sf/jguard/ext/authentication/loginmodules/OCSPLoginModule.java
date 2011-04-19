/*
 jGuard is a security framework based on top of jaas (java authentication and authorization security).
 it is written for web applications, to resolve simply, access control problems.
 version $Name$
 http://sourceforge.net/projects/jguard/

 Copyright (C) 2004  Charles GAY

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


 jGuard project home page:
 http://sourceforge.net/projects/jguard/

 */
package net.sf.jguard.ext.authentication.loginmodules;

import net.sf.jguard.ext.SecurityConstants;
import org.bouncycastle.ocsp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Check the revocation status of a public key certificate using <acronym title="Online Certificate Status Protocol">OCSP</acronym>.
 * this class comes from the EJBCA project. the <a href="http://ejbca.sourceforge.net/">EJBCA</a> project is released under the
 * <a href="http://www.gnu.org/copyleft/lesser.html">LGPL</a> licence. licence, like the jGuard project.
 *
 * @author <a href="mailto:simon.lebettre[at)gmail.com">Simon Lebettre</a>
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class OCSPLoginModule extends CertificateLoginModule implements LoginModule {

    private static final String X509 = "X509";
    private static final String CONTENT_TYPE = "Content-Type";
    private static final String APPLICATION_OCSP_REQUEST = "application/ocsp-request";
    private static final String POST = "POST";
    private static final String BC = "BC";
    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(OCSPLoginModule.class.getName());
    private Map sharedState;
    private Map options;

    private URL ocspServerUrl;
    private X509Certificate issuerCACert;
    private String issuerCACertLocation;
    private X509Certificate OcspSignerCert;
    private String OcspSignerCertLocation;
    private Object certStatus = null;
    private static boolean SecurityProviderInitialized = false;

    /**
     * initialize the LoginModule with the required issuer, the OCSP server certificates and its adress.
     *
     * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject,
     *      javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     */
    public void initialize(Subject subj, CallbackHandler cbkHandler, Map sState, Map opts) {
        super.subject = subj;
        this.callbackHandler = cbkHandler;
        this.sharedState = sState;
        this.options = opts;

        if (!SecurityProviderInitialized) {
            SecurityProviderInitialized = CRLLoginModule.initSecurityProvider();
        }

        try {
            ocspServerUrl = new URL((String) options.get(SecurityConstants.OCSP_SERVER_URL));
        } catch (MalformedURLException e) {
            logger.error("ocspServerUrl=" + ocspServerUrl + " is malformed");
            throw new IllegalArgumentException(e.getMessage(),e);
        }
        issuerCACertLocation = (String) options.get(SecurityConstants.ISSUER_CA_CERT_LOCATION);
        try {
            issuerCACert = getCertFromFile(issuerCACertLocation);
            OcspSignerCertLocation = (String) options.get(SecurityConstants.OCSP_SIGNER_CERT_LOCATION);
            OcspSignerCert = getCertFromFile(OcspSignerCertLocation);
        } catch (CertificateException e) {
            logger.error("", e);
            throw new IllegalArgumentException(e.getMessage(),e);
        }

        if (!issuerCACert.equals(OcspSignerCert)) {
            throw new UnsupportedOperationException("Having a CA cert different "
                    + "from ocspSigner cert is not currently supported," + " the ocsp response is signed by the CA ");
        }

    }

    /**
     * verify either user is registered or not.
     *
     * @see javax.security.auth.spi.LoginModule#login()
     */
    public boolean login() throws LoginException {
        boolean login = super.login();
        if (!login) {
            return login;
        }
        byte[] ocspRequest;
        try {
            OCSPResp response = null;
            try {
                ocspRequest = generateOcspRequest(certChainToCheck);
                byte[] respBytes = getResponseFromHttp(ocspRequest, ocspServerUrl);
                response = new OCSPResp(new ByteArrayInputStream(respBytes));
            } catch (IOException e) {
                logger.error(" IOException when we build the OCSPResponse from HTTP ", e);

            }

            BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
            X509Certificate[] chain = brep.getCerts(OCSPLoginModule.BC);
            boolean verify = brep.verify(chain[0].getPublicKey(), OCSPLoginModule.BC);

            if (!verify) {
                loginOK = false;
                throw new LoginException(" OCSP response is not valid ");
            }

            SingleResp[] singleResps = brep.getResponses();
            for (SingleResp singleResp : singleResps) {
                certStatus = singleResp.getCertStatus();
                // when the status object is null, the response is good (@see org.bouncycastle.ocsp.SingleResp )

                if (certStatus == null) {
                    continue;
                } else {
                    loginOK = false;
                    throw new FailedLoginException(" status is not null. 'null' is the success result " + certStatus.toString());
                }
            }

        } catch (OCSPException e) {
            throw new LoginException(e.getMessage());
        } catch (NoSuchProviderException e) {
            throw new LoginException(e.getMessage());
        }
        //like we've already check user credentials present in the certificate
        //password check must not be done one more time.
        sharedState.put(SKIP_CREDENTIAL_CHECK, "true");
        return true;

    }

    /**
     * ask from the OCSP server if the certificate is valid.
     *
     * @param ocspPackage
     * @param url
     * @return response from the OCSP server.
     * @throws IOException
     * @throws IOException
     * @throws ProtocolException
     */
    private byte[] getResponseFromHttp(byte[] ocspPackage, URL url) throws IOException {
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setDoOutput(true);
        try {
            con.setRequestMethod(OCSPLoginModule.POST);
        } catch (ProtocolException e) {
            throw new IOException(e.getMessage(),e);
        }

        con.setRequestProperty(OCSPLoginModule.CONTENT_TYPE, OCSPLoginModule.APPLICATION_OCSP_REQUEST);
        OutputStream os = null;
        try {
            os = con.getOutputStream();
            os.write(ocspPackage);
        } catch (IOException e) {
            logger.error(e.getMessage());
            throw e;
        } finally {
            os.close();
        }
        InputStream in = null;
        byte[] respBytes = null;
        ByteArrayOutputStream baos = null;
        try {
            baos = new ByteArrayOutputStream();

            // This works for small requests, and OCSP requests are small
            in = con.getInputStream();
            int b = in.read();
            while (b != -1) {
                baos.write(b);
                b = in.read();
            }
            baos.flush();
        } finally {
            in.close();
            con.disconnect();
        }
        respBytes = baos.toByteArray();
        return respBytes;

    }

    /**
     * generate the OCSP request.
     *
     * @param certsToCheck
     * @return byte[] ocsp request
     * @throws OCSPException
     * @throws IOException
     */
    private byte[] generateOcspRequest(X509Certificate[] certsToCheck) throws OCSPException, IOException {
        OCSPReqGenerator gen = new OCSPReqGenerator();
        for (X509Certificate certToCheck : certsToCheck) {
            gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, issuerCACert, certToCheck.getSerialNumber()));
        }
        OCSPReq req = gen.generate();
        return req.getEncoded();
    }


    /**
     * Read a certificate from the specified filepath.
     *
     * @param path
     * @return certificate
     * @throws CertificateException
     */
    public static X509Certificate getCertFromFile(String path) throws CertificateException {
        X509Certificate cert = null;

        File certFile = new File(path);
        if (!certFile.canRead()) {
            logger.error(" File " + certFile.toString() + " is unreadable");
            throw new CertificateException(" File " + certFile.toString() + " is unreadable");

        }
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(path);
            CertificateFactory cf;
            cf = CertificateFactory.getInstance(OCSPLoginModule.X509);
            cert = (X509Certificate) cf.generateCertificate(fis);
        } catch (FileNotFoundException e) {
            logger.error("we cannot found the certificate file here:" + path, e);
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
            } catch (IOException e) {
                logger.error(e.getMessage());
            }
        }


        return cert;
    }

}
