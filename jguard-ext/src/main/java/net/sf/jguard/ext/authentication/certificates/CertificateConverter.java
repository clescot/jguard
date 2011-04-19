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
package net.sf.jguard.ext.authentication.certificates;

import javax.security.cert.CertificateException;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;

/**
 * Class inspired from <a href="http://javaalmanac.com/egs/javax.security.cert/ConvertCert.html">a javaalmanach example</a>.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net ">Charles Gay</a>
 */
public class CertificateConverter {
    private static final String X_509 = "X.509";

    /**
     * convert a jav<b>ax</b>.security.cert.X509Certificate  to a jav<b>a</b>.security.cert.X509Certificate.
     *
     * @param cert
     * @return X509Certificate
     */
    public static java.security.cert.X509Certificate convertOldToNew(javax.security.cert.X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance(CertificateConverter.X_509);
            return (java.security.cert.X509Certificate) cf.generateCertificate(bis);
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (javax.security.cert.CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (java.security.cert.CertificateException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * convert a <code>java.security.cert.X509Certificate</code> to a <code>javax.security.cert.X509Certificate</code>.
     *
     * @param cert
     * @return X509Certificate
     */
    public static javax.security.cert.X509Certificate convertNewToOld(java.security.cert.X509Certificate cert) throws CertificateException, CertificateEncodingException {

        byte[] encoded = cert.getEncoded();
        return javax.security.cert.X509Certificate.getInstance(encoded);

    }


}
