/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.

http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles Lescot

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
package net.sf.jguard.ext.authentication.certificates;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Utility class to handle X509 certificates.
 *
 * @author <a href="mailto:slebettre@gmail.com">Simon Lebettre</a>
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class CertUtils {

    private static final String X509 = "X509";
    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(CertUtils.class.getName());

    /**
     * Read a certificate from the specified filepath.
     *
     * @param path
     * @return X509Certificate
     */
    public static X509Certificate getCertFromFile(String path) {
        X509Certificate cert = null;

        File certFile = new File(path);
        if (!certFile.canRead()) {
            logger.error(" File " + certFile.toString() + " is unreadable");
            return null;
        }
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(path);
        } catch (FileNotFoundException e) {
            logger.error("", e);
            return null;

        }
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance(CertUtils.X509);
            cert = (X509Certificate) cf.generateCertificate(fis);
        } catch (CertificateException e) {
            logger.error("", e);
            return null;
        } finally {
            try {
                fis.close();
            } catch (IOException e) {
                logger.error("", e);
            }
        }

        return cert;
    }

    /**
     * return all the certificates contained in the directory path.
     *
     * @param directoryPath
     * @return certificates Set, an empty Set if the directoryPath is null
     */
    public static Set getCertsFromDirectory(String directoryPath) {
        Set certsSet = new HashSet();
        if (directoryPath == null) {
            return certsSet;
        }
        File file = new File(directoryPath);
        List filesAndDirectories = Arrays.asList(file.listFiles());

        for (Object filesAndDirectory : filesAndDirectories) {
            File tempFile = (File) filesAndDirectory;
            if (tempFile.isFile()) {
                certsSet.add(getCertFromFile(tempFile.getPath()));
            }
        }

        return certsSet;
    }

    /**
     * return a Set of TrustAnchors (without nameConstraints)
     * which comes from a directory path.
     *
     * @param directoryPath
     * @return TrustAnchor Set
     */
    public static Set getTrustedAnchorsFromDirectory(String directoryPath) {
        Set trustedAnchors = new HashSet();
        Set certs = getCertsFromDirectory(directoryPath);
        for (Object cert1 : certs) {
            X509Certificate cert = (X509Certificate) cert1;
            TrustAnchor trustAnchor = new TrustAnchor(cert, null);
            trustedAnchors.add(trustAnchor);
        }
        return trustedAnchors;
    }

    /**
     * return a Set of TrustAnchors (without nameConstraints)
     * which comes from a directory path.
     *
     * @param directoryPath
     * @param nameConstraints constraints applied to all the TrustAnchor
     * @return TrustAnchor Set
     */
    public static Set getTrustedAnchorsFromDirectory(String directoryPath, byte[] nameConstraints) {
        Set trustedAnchors = new HashSet();
        Set certs = getCertsFromDirectory(directoryPath);
        for (Object cert1 : certs) {
            X509Certificate cert = (X509Certificate) cert1;
            TrustAnchor trustAnchor = new TrustAnchor(cert, nameConstraints);
            trustedAnchors.add(trustAnchor);
        }
        return trustedAnchors;
    }

    /**
     * output the CRL content.
     *
     * @param crl to inspect
     */
    private void inspectCRL(X509CRL crl) {
        if (logger.isDebugEnabled()) {
            logger.debug("crl=" + crl.toString());
            logger.debug("crlType=" + crl.getType());
            logger.debug("crl next update Date=" + crl.getNextUpdate());
            logger.debug("crl issuer DN=" + crl.getIssuerDN().getName());
            logger.debug("crl signature algorithm name =" + crl.getSigAlgName());
            logger.debug("crl signature algorithm oid =" + crl.getSigAlgOID());
            logger.debug("crl version =" + crl.getVersion());
            logger.debug("crl update Date =" + crl.getThisUpdate());
        }
        Set revokedCertificates = crl.getRevokedCertificates();
        for (Object revokedCertificate : revokedCertificates) {
            X509Certificate certificate = (X509Certificate) revokedCertificate;
            logger.debug(certificate.toString());
        }
        Set criticalExtensions = crl.getCriticalExtensionOIDs();
        for (Object criticalExtension : criticalExtensions) {
            String oid = (String) criticalExtension;
            logger.debug(" critical extension = " + oid);
        }
        Set nonCriticalExtensions = crl.getNonCriticalExtensionOIDs();
        for (Object nonCriticalExtension : nonCriticalExtensions) {
            String oid = (String) nonCriticalExtension;
            logger.debug(" non critical extension = " + oid);
        }

    }

    public static KeyStore getKeyStore(String filePath, String keyStorePassword, String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filePath);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        KeyStore keystore = KeyStore.getInstance(keyStoreType);
        keystore.load(fis, keyStorePassword.toCharArray());
        return keystore;
    }

}
