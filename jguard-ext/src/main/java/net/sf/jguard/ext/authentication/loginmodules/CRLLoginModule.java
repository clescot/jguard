/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.

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

import net.sf.jguard.core.authentication.configuration.JGuardAuthenticationMarkups;
import net.sf.jguard.ext.SecurityConstants;
import net.sf.jguard.ext.authentication.certificates.CertUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * validate certificates: validate their certPath and checks if
 * some of them are revoked against CRL(Certificate Revocation list).
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net ">Charles Gay</a>
 */
public class CRLLoginModule extends CertificateLoginModule implements LoginModule {

    private static final String COLLECTION = "Collection";
    private static final String LDAP = "LDAP";
    private static final String PKIX = "PKIX";
    private static final String X_509 = "X.509";

    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(CRLLoginModule.class.getName());
    private Set trustAnchors = null;
    private String trustedCaCertsDirPath = null;
    private CertPath certPath = null;
    private boolean debug = false;
    private Provider securityProvider = null;
    private String certStoreType = CRLLoginModule.LDAP;
    private String ldapServerName = "localhost";
    private static int LDAP_SERVER_PORT;
    private static final int DEFAULT_LDAP_SERVER_PORT = 389;
    private Map sharedState;
    private String fileCrlPath = null;
    private String urlCrlPath = null;
    private boolean anyPolicyInhibited = false;
    private boolean explicitPolicyRequired = false;
    private boolean policyMappingInhibited = false;
    private boolean policyQualifierRejected = true;
    private boolean revocationEnabled = true;
    private String sigProvider = null;
    private String keyStorePath;
    private String keyStorePassword;
    private String keyStoreType;
    private static boolean SecurityProviderInitialized = false;


    /**
     * @param subj
     * @param cbkHandler
     * @param state
     * @param options
     * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     */
    public void initialize(Subject subj, CallbackHandler cbkHandler, Map state, Map options) {
        this.subject = subj;
        this.callbackHandler = cbkHandler;
        this.sharedState = state;

        if (!SecurityProviderInitialized) {
            SecurityProviderInitialized = initSecurityProvider();
        }

        if (options.get(JGuardAuthenticationMarkups.DEBUG.getLabel()) != null) {
            debug = Boolean.valueOf((String) options.get(JGuardAuthenticationMarkups.DEBUG.getLabel()));
        }

        if (options.get(SecurityConstants.CERT_PATH_ANY_POLICY_INHIBITED) != null) {
            anyPolicyInhibited = Boolean.valueOf((String) options.get(SecurityConstants.CERT_PATH_ANY_POLICY_INHIBITED));
        }

        if (options.get(SecurityConstants.CERT_PATH_EXPLICIT_POLICY_REQUIRED) != null) {
            explicitPolicyRequired = Boolean.valueOf((String) options.get(SecurityConstants.CERT_PATH_EXPLICIT_POLICY_REQUIRED));
        }

        if (options.get(SecurityConstants.CERT_PATH_POLICY_MAPPING_INHIBITED) != null) {
            policyMappingInhibited = Boolean.valueOf((String) options.get(SecurityConstants.CERT_PATH_POLICY_MAPPING_INHIBITED));
        }

        if (null != options.get(SecurityConstants.CERT_PATH_POLICY_QUALIFIERS_REJECTED)) {
            policyQualifierRejected = Boolean.valueOf((String) options.get(SecurityConstants.CERT_PATH_POLICY_QUALIFIERS_REJECTED));
        }

        if (options.get(SecurityConstants.CERT_PATH_REVOCATION_ENABLED) != null) {
            revocationEnabled = Boolean.valueOf((String) options.get(SecurityConstants.CERT_PATH_REVOCATION_ENABLED));
        }

        if (options.get(SecurityConstants.CERT_PATH_SIG_PROVIDER) != null) {
            sigProvider = (String) options.get(SecurityConstants.CERT_PATH_SIG_PROVIDER);
        }

        if (options.get(SecurityConstants.CERT_PATH_CRL_PATH) != null) {
            fileCrlPath = (String) options.get(SecurityConstants.CERT_PATH_CRL_PATH);
        }

        if (options.get(SecurityConstants.CERT_PATH_URL_CRL_PATH) != null) {
            urlCrlPath = (String) options.get(SecurityConstants.CERT_PATH_URL_CRL_PATH);
        }

        if (options.get(SecurityConstants.TRUSTED_CA_CERTIFICATES_DIRECTORY_PATH) != null) {
            trustedCaCertsDirPath = (String) options.get(SecurityConstants.TRUSTED_CA_CERTIFICATES_DIRECTORY_PATH);
            trustAnchors = CertUtils.getTrustedAnchorsFromDirectory(trustedCaCertsDirPath);
        }

        if (options.get(SecurityConstants.SECURITY_PROVIDER) != null) {
            String securityProviderClassName = (String) options.get(SecurityConstants.SECURITY_PROVIDER);
            try {
                Class securityProviderClass = this.getClass().getClassLoader().loadClass(securityProviderClassName);
                securityProvider = (Provider) securityProviderClass.newInstance();

            } catch (ClassNotFoundException e) {
                logger.warn(e.getMessage());
            } catch (InstantiationException e) {
                logger.warn(e.getMessage());
            } catch (IllegalAccessException e) {
                logger.warn(e.getMessage());
            }
        } else {
            securityProvider = new BouncyCastleProvider();
        }

        if (options.get(SecurityConstants.CERT_PATH_CERTSTORE_TYPE) != null) {
            certStoreType = (String) options.get(SecurityConstants.CERT_PATH_CERTSTORE_TYPE);
        }

        if (options.get(SecurityConstants.CERT_PATH_LDAP_SERVER_NAME) != null) {
            ldapServerName = (String) options.get(SecurityConstants.CERT_PATH_LDAP_SERVER_NAME);
        }

        if (options.get(SecurityConstants.CERT_PATH_LDAP_SERVER_PORT) != null) {
            LDAP_SERVER_PORT = Integer.parseInt((String) options.get(SecurityConstants.CERT_PATH_LDAP_SERVER_PORT));
        } else {
            LDAP_SERVER_PORT = DEFAULT_LDAP_SERVER_PORT;
        }

        if (options.get(SecurityConstants.JAVAX_NET_SSL_TRUSTSTORE) != null) {
            String trustStoreFileName = (String) options.get(SecurityConstants.JAVAX_NET_SSL_TRUSTSTORE);
            System.setProperty(SecurityConstants.JAVAX_NET_SSL_TRUSTSTORE, trustStoreFileName);
        }

        if (options.get(SecurityConstants.JAVAX_NET_SSL_TRUSTSTORE_PASSWORD) != null) {
            String trustStorePassword = (String) options.get(SecurityConstants.JAVAX_NET_SSL_TRUSTSTORE_PASSWORD);
            System.setProperty(SecurityConstants.JAVAX_NET_SSL_TRUSTSTORE_PASSWORD, trustStorePassword);
        }

        if (options.get(SecurityConstants.KEY_STORE_PATH) != null) {
            keyStorePath = (String) options.get(SecurityConstants.KEY_STORE_PATH);
        }

        if (options.get(SecurityConstants.KEY_STORE_PASSWORD) != null) {
            keyStorePassword = (String) options.get(SecurityConstants.KEY_STORE_PASSWORD);
        }

        if (options.get(SecurityConstants.KEY_STORE_TYPE) != null) {
            keyStoreType = (String) options.get(SecurityConstants.KEY_STORE_TYPE);
        }


    }

    /**
     * @see javax.security.auth.spi.LoginModule#login()
     */
    public boolean login() throws LoginException {

        boolean login = super.login();
        if (!login) {
            return login;
        }
        certPath = buildCertPath(certChainToCheck);
        validateCertPath(certPath);
        //like we've already check user credentials present in the certificate
        //password check must not be done one more time.
        sharedState.put(SKIP_CREDENTIAL_CHECK, "true");
        return true;
    }


    /**
     * generate certification Path .
     *
     * @param certs the X509Certificate Array
     * @return certification path
     */
    private CertPath buildCertPath(X509Certificate[] certs) {
        CertificateFactory certFactory;
        CertPath certPath = null;
        try {
            certFactory = CertificateFactory.getInstance(CRLLoginModule.X_509, securityProvider);
            certPath = certFactory.generateCertPath(Arrays.asList(certs));
        } catch (CertificateException e) {
            logger.warn(e.getMessage());
        }

        return certPath;
    }


    /**
     * validate a certPath.
     *
     * @param certPath
     * @throws LoginException
     */
    private void validateCertPath(CertPath certPath) throws LoginException {
        CertPathValidator validator = null;
        PKIXParameters parameters;
        PKIXCertPathValidatorResult result;
        try {
            validator = CertPathValidator.getInstance(CRLLoginModule.PKIX, securityProvider);

        } catch (NoSuchAlgorithmException e) {
            logger.error(" algorithm PKIX is not present " + securityProvider.getName()
                    + " " + securityProvider.getInfo() + " " + securityProvider.getVersion());
        }
        try {

            parameters = getPKIXParameters();
            List certStores = new ArrayList();
            CertStore certStore = getCertStore();
            certStores.add(certStore);
            parameters.setCertStores(certStores);
            parameters.setAnyPolicyInhibited(anyPolicyInhibited);
            //TODO implement better data handling (more precise)
            parameters.setDate(new Date());
            //TODO howto implements the CRLSelector => with certStore?
            parameters.setExplicitPolicyRequired(explicitPolicyRequired);
            parameters.setPolicyMappingInhibited(policyMappingInhibited);
            parameters.setPolicyQualifiersRejected(policyQualifierRejected);
            parameters.setRevocationEnabled(revocationEnabled);
            if (sigProvider != null) {
                parameters.setSigProvider(sigProvider);
            }
            //TODO define the certSelector
            //parameters.setTargetCertConstraints(null);
            //
            result = (PKIXCertPathValidatorResult) validator.validate(certPath, parameters);
            PolicyNode policyTree = result.getPolicyTree();
            PublicKey key = result.getPublicKey();
            TrustAnchor anchor = result.getTrustAnchor();
            if (debug) {
                if (policyTree != null) {
                    logger.debug("policyTree depth = " + policyTree.getDepth());
                    logger.debug("policyTree expected policies = " + policyTree.getExpectedPolicies());
                    logger.debug("policyTree policy qualifiers = " + policyTree.getPolicyQualifiers());
                }
                if (key != null) {
                    logger.debug("public key= " + key.toString());
                }
                if (anchor != null) {
                    logger.debug("TrustAnchor ca name= " + anchor.getCAName());
                    logger.debug("TrustAnchor ca public key = " + anchor.getCAPublicKey());
                    logger.debug("TrustAnchor name constraints = " + new String(anchor.getNameConstraints()));
                    logger.debug("TrustAnchor trustedCert = " + anchor.getTrustedCert());
                }
            }
        } catch (InvalidAlgorithmParameterException e) {
            logger.error(e.getMessage());
            throw new FailedLoginException(e.getMessage());
        } catch (CertPathValidatorException e) {
            logger.error(e.getMessage());
            throw new FailedLoginException(e.getMessage());
        }
    }

    private PKIXParameters getPKIXParameters() throws LoginException {
        PKIXParameters parameters = null;
        if (keyStorePath != null) {
            KeyStore keystore;
            try {
                keystore = CertUtils.getKeyStore(keyStorePath, keyStorePassword, keyStoreType);
                parameters = new PKIXParameters(keystore);
            } catch (KeyStoreException e) {
                throw new LoginException(e.getMessage());
            } catch (NoSuchAlgorithmException e) {
                throw new LoginException(e.getMessage());
            } catch (CertificateException e) {
                throw new LoginException(e.getMessage());
            } catch (IOException e) {
                throw new LoginException(e.getMessage());
            } catch (InvalidAlgorithmParameterException e) {
                throw new LoginException(e.getMessage());
            }

        } else {
            try {
                parameters = new PKIXParameters(trustAnchors);
            } catch (InvalidAlgorithmParameterException e) {
                throw new LoginException(e.getMessage());
            }
        }
        return parameters;
    }


    /**
     * retrieve the certStore.
     *
     * @return certStore
     * @throws LoginException the certStore valueType is invalid
     */
    private CertStore getCertStore() throws LoginException {
        CertStore certStore;

        //build a certStoreParameters object
        CertStoreParameters certStoreParams;
        if (certStoreType.equalsIgnoreCase(CRLLoginModule.LDAP)) {
            certStoreParams = new LDAPCertStoreParameters(ldapServerName, LDAP_SERVER_PORT);
        } else if (certStoreType.equalsIgnoreCase(CRLLoginModule.COLLECTION)) {
            Collection crlCollection = getCRLAndCertsCollection();
            certStoreParams = new CollectionCertStoreParameters(crlCollection);
        } else {
            throw new LoginException(" invalid 'certStoreType' value : this value should be 'LDAP' or 'Collection' ");
        }
        try {
            //build a CRL certStore
            certStore = CertStore.getInstance(certStoreType, certStoreParams, securityProvider);

        } catch (NoSuchAlgorithmException e) {
            throw new LoginException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            throw new LoginException(e.getMessage());
        }

        return certStore;
    }

    /**
     * retrieve Certificate Revocation List (CRL) and Certificates.
     *
     * @return collection of CRL and Certificates
     */
    private Collection getCRLAndCertsCollection() {
        Collection crlAndCerts = new ArrayList();
        CertificateFactory certFactory = null;
        try {
            certFactory = CertificateFactory.getInstance(CRLLoginModule.X_509, securityProvider);
        } catch (CertificateException e) {
            logger.error(" X509 certificate factory cannot be retrieved with the securityProvider " +
                    securityProvider.getName() + " " + securityProvider.getInfo() +
                    " " + securityProvider.getVersion(), e);
        }

        if (fileCrlPath != null) {
            addCRLFromPath(crlAndCerts, certFactory);
        }
        if (urlCrlPath != null) {
            addCRLFromURL(crlAndCerts, certFactory);
        }
        return crlAndCerts;
    }

    /**
     * add <b>ONE</b> CRL grabbed from a file path to the 'CRLs and Certs' Collection.
     *
     * @param crlAndCerts
     * @param certFactory
     */
    private void addCRLFromPath(Collection<CRL> crlAndCerts, CertificateFactory certFactory) {

        InputStream stream = null;
        try {
            stream = new BufferedInputStream(new FileInputStream(fileCrlPath));
        } catch (FileNotFoundException e) {
            logger.error(e.getMessage(), e);
        }
        try {
            CRL crl = certFactory.generateCRL(stream);
            crlAndCerts.add(crl);
        } catch (CRLException e) {
            logger.error(e.getMessage(), e);
        } finally {
            try {
                if (stream != null) {
                    stream.close();
                }
            } catch (IOException e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    /**
     * add <b>ONE</b> CRL grabbed from an URL to the 'CRLs and Certs' Collection.
     *
     * @param crlAndCerts
     * @param certFactory
     */
    private void addCRLFromURL(Collection<CRL> crlAndCerts, CertificateFactory certFactory) {
        DataInputStream data = null;
        try {
            URL url = new URL(urlCrlPath);
            URLConnection connection = url.openConnection();
            //we retrieve content
            connection.setDoInput(true);
            //we do not permit to cache content
            connection.setUseCaches(false);
            data = new DataInputStream(connection.getInputStream());

            CRL crl = certFactory.generateCRL(data);
            crlAndCerts.add(crl);
        } catch (MalformedURLException e) {
            logger.error(" bad uri synthax " + urlCrlPath, e);
        } catch (IOException e) {
            logger.error(" IOException when we wan to retrieve CRL with data ", e);
        } catch (CRLException e) {
            logger.error(" CRL cannot be built with the retrieved data ");
        } finally {
            try {
                if (data != null) {
                    data.close();
                }
            } catch (IOException e) {
                logger.error(" IOException when we close the DATAInputStream", e);
            }
        }
    }

    /**
     * install BouncyCastleProvider in the secuirty providers
     * stack of the java platform.
     *
     * @return true if installation succeed, false otherwise
     */
    protected static boolean initSecurityProvider() {
        if (Security.getProvider(BouncyCastleProvider.class.getName()) == null) {
            try {
                Security.addProvider(new BouncyCastleProvider());
                return true;
            } catch (SecurityException sex) {
                logger.error(" jGuard cannot add dynamically the JCE provider required from  \n");
                logger.error(" the BOUNCYCASTLE library .this operation is prevented by the SECURITYMANAGER \n");
                logger.error(" to use this required provider, you must add an entry to your java.security  \n");
                logger.error(" properties file (found in $JAVA_HOME/jre/lib/security/java.security, \n");
                logger.error(" where $JAVA_HOME is the location of your JDK/JRE distribution) \n");
                logger.error(" security.provider.<n>=org.bouncycastle.jce.provider.BouncyCastleProvider \n");
                logger.error("  Where <n> is the preference you want the provider at (1 being the most prefered). ");
                return false;
            }
        } else {
            return true;
        }
    }

}
