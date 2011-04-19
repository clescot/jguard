/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name:  $
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
package net.sf.jguard.ext.authentication.callbacks;

import net.sf.jguard.core.authentication.callbacks.CertificatesCallback;
import net.sf.jguard.core.authentication.callbacks.GuestCallbacksProvider;
import net.sf.jguard.ext.authentication.certificates.CertificateConverter;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class for {@link CallbackHandler}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net ">Charles Gay</a>
 */
public class CallbackHandlerUtils {
    private static final String DIGEST_REALM = "Digest realm=\"";
    private static final Logger logger = LoggerFactory.getLogger(CallbackHandlerUtils.class.getName());
    private static final String ISO_8859_1 = "ISO-8859-1";
    private static final String BASIC = "Basic ";

    public static final String JAVAX_SERVLET_REQUEST_X509CERTIFICATE = "javax.servlet.request.X509Certificate";
    private static final String[] EMPTY_STRING = new String[0];
    private static final String DOUBLE_EQUALS = "==";

    public static void fillBasicCredentials(Callback[] callbacks, String login, String password) {
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback nc = (NameCallback) callback;
                nc.setName(login);

            } else if (callback instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback) callback;
                pc.setPassword(password.toCharArray());
            } else if (callback instanceof JCaptchaCallback) {
                JCaptchaCallback jc = (JCaptchaCallback) callback;
                //we skip JCaptcha because we cannot provide
                //CAPTCHA challenge through BASIC authentication
                jc.setSkipJCaptchaChallenge(true);
            }
        }
    }

    public static boolean grabClientCertCredentials(Callback[] callbacks,
                                                    Object[] objects) {
        X509Certificate[] certificates = null;
        javax.security.cert.X509Certificate[] oldCerts = null;
        if (objects == null || objects.length == 0) {
            return false;
        }

        if (objects instanceof X509Certificate[]) {
            certificates = (X509Certificate[]) objects;
            //convert old X509 certificates into new X509 certificates
        } else if (objects instanceof javax.security.cert.X509Certificate[]) {
            oldCerts = (javax.security.cert.X509Certificate[]) objects;
            List<X509Certificate> newCerts = null;
            for (javax.security.cert.X509Certificate oldCert : oldCerts) {
                newCerts = Arrays.asList(certificates);
                newCerts.add(CertificateConverter.convertOldToNew(oldCert));
            }
            if (newCerts != null) {
                certificates = (X509Certificate[]) newCerts.toArray();
            }
        } else {
            logger.warn(" X509certificates are needed but not provided by the client ");
            return false;
        }
        CallbackHandlerUtils.fillCertCredentials(callbacks, certificates);

        return true;
    }

    public static boolean grabBasicCredentials(String encodedLoginAndPwd, String encoding, Callback[] callbacks) {
        boolean result = false;
        String login = "";
        String password = "";
        if (encodedLoginAndPwd == null || encodedLoginAndPwd.equals("")) {
            login = GuestCallbacksProvider.GUEST;
            password = GuestCallbacksProvider.GUEST;

        } else {
            encodedLoginAndPwd = encodedLoginAndPwd.substring(6).trim();
            String decodedLoginAndPassword = null;


            if (encoding == null) {
                encoding = CallbackHandlerUtils.ISO_8859_1;
            }
            logger.debug(encoding);

            try {
                decodedLoginAndPassword = new String(Base64.decode(encodedLoginAndPwd.getBytes()), encoding);
            } catch (UnsupportedEncodingException e) {
                logger.debug(" encoding " + encoding + " is not supported by the platform ", e);
            }

            String[] parts = EMPTY_STRING;
            if (decodedLoginAndPassword != null) {
                parts = decodedLoginAndPassword.split(":");
            }
            if (parts.length == 2) {
                login = parts[0].trim();
                password = parts[1].trim();

                result = true;
            }
            if (("".equals(login) && "".equals(password)) || (parts.length == 0)) {
                login = GuestCallbacksProvider.GUEST;
                password = GuestCallbacksProvider.GUEST;
            }

        }

        CallbackHandlerUtils.fillBasicCredentials(callbacks, login, password);
        return result;
    }

    /**
     * construct a header value to simulate a Basic authentication with the provided credentials.
     *
     * @param login
     * @param password
     * @param encoding encoding destination scheme. if encoding is null, ISO_8859-1 is used (ISO_LATIN_1).
     * @return header containing login and pasword in base 64, separated by a colon and encoded.
     */
    public static String buildBasicAuthHeader(String login, String password, String encoding) {
        if (encoding == null) {
            encoding = CallbackHandlerUtils.ISO_8859_1;
        }
        StringBuffer decodedString = new StringBuffer();
        decodedString.append(login);
        decodedString.append(" : ");
        decodedString.append(password);
        String encodedString;
        try {
            encodedString = new String(Base64.encode(decodedString.toString().getBytes(encoding)));
        } catch (UnsupportedEncodingException e) {
            encodedString = new String(Base64.encode(decodedString.toString().getBytes()));
        }
        StringBuffer header = new StringBuffer();
        header.append(CallbackHandlerUtils.BASIC);
        header.append(encodedString);
        header.append(DOUBLE_EQUALS);
        return header.toString();
    }


    public static String buildDigestChallenge(String realm) {
        //TODO buildDigestChallenge method is not complete
        StringBuffer responseValue = new StringBuffer();
        //what about domain which defines the protection space?

        //realm
        responseValue.append(CallbackHandlerUtils.DIGEST_REALM);
        responseValue.append(realm);
        responseValue.append("\"");
        responseValue.append(",");
        //quality of protection qop
        responseValue.append("qop=\"");
        responseValue.append(getQop());
        responseValue.append("\"");
        responseValue.append(",");

        responseValue.append("nonce=\"");
        responseValue.append(getNonce());
        responseValue.append("\"");
        responseValue.append(",");
        //opaque
        responseValue.append("opaque=");
        responseValue.append("\"");
        responseValue.append(getOpaque());
        responseValue.append("\"");
        //algorithm
        responseValue.append("algorithm=");
        responseValue.append("\"");
        responseValue.append(getAlgorithm());
        responseValue.append("\"");
        //stale
        responseValue.append("stale=");
        responseValue.append("\"");
        responseValue.append(getStale());
        responseValue.append("\"");

        return responseValue.toString();
    }


    /**
     * A flag, indicating that the previous request from the client was
     * rejected because the nonce value was stale. If stale is TRUE
     * (case-insensitive), the client may wish to simply retry the request
     * with a new encrypted response, without reprompting the user for a
     * new username and password. The server should only set stale to TRUE
     * if it receives a request for which the nonce is invalid but with a
     * valid digest for that nonce (indicating that the client knows the
     * correct username/password). If stale is FALSE, or anything other
     * than TRUE, or the stale directive is not present, the username
     * and/or password are invalid, and new values must be obtained
     *
     * @return
     */
    private static String getStale() {
        return "false";
    }

    /**
     * This directive is optional, but is made so only for backward
     * compatibility with RFC 2069 [6]; it SHOULD be used by all
     * implementations compliant with this version of the Digest scheme.
     * If present, it is a quoted string of one or more tokens indicating
     * the "quality of protection" values supported by the server.  The
     * value "auth" indicates authentication; the value "auth-int"
     * indicates authentication with integrity protection; see the
     * descriptions below for calculating the response directive value for
     * the application of this choice. Unrecognized options MUST be
     * ignored.
     *
     * @return
     */
    private static String getQop() {
        return "auth,auth-int";
    }

    /**
     * A string of data, specified by the server, which should be returned
     * by the client unchanged in the Authorization header of subsequent
     * requests with URIs in the same protection space. It is recommended
     * that this string be base64 or hexadecimal data.
     *
     * @return
     */
    private static String getOpaque() {
        return "5ccc069c403ebaf9f0171e9517f40e41";
    }

    /**
     * A string indicating a pair of algorithms used to produce the digest
     * and a checksum. If this is not present it is assumed to be "MD5".
     * If the algorithm is not understood, the challenge should be ignored
     * (and a different one used, if there is more than one).
     * <p/>
     * In this document the string obtained by applying the digest
     * algorithm to the data "data" with secret "secret" will be denoted
     * by KD(secret, data), and the string obtained by applying the
     * checksum algorithm to the data "data" will be denoted H(data). The
     * notation unq(X) means the value of the quoted-string X without the
     * surrounding quotes.
     * <p/>
     * For the "MD5" and "MD5-sess" algorithms
     * <p/>
     * H(data) = MD5(data)
     * <p/>
     * and
     * <p/>
     * KD(secret, data) = H(concat(secret, ":", data))
     * <p/>
     * i.e., the digest is the MD5 of the secret concatenated with a colon
     * concatenated with the data. The "MD5-sess" algorithm is intended to
     * allow efficient 3rd party authentication servers; for the
     * difference in usage, see the description in section 3.2.2.2.
     *
     * @return
     */
    private static String getAlgorithm() {
        return "MD5";
    }

    /**
     * //nonce
     * <p/>
     * A server-specified data string which should be uniquely generated
     * each time a 401 response is made. It is recommended that this
     * string be base64 or hexadecimal data. Specifically, since the
     * string is passed in the header lines as a quoted string, the
     * double-quote character is not allowed.
     * <p/>
     * The contents of the nonce are implementation dependent. The quality
     * of the implementation depends on a good choice. A nonce might, for
     * example, be constructed as the base 64 encoding of
     * <p/>
     * time-stamp H(time-stamp ":" ETag ":" private-key)
     * <p/>
     * where time-stamp is a server-generated time or other non-repeating
     * value, ETag is the value of the HTTP ETag header associated with
     * the requested entity, and private-key is data known only to the
     * server.  With a nonce of this form a server would recalculate the
     * hash portion after receiving the client authentication header and
     * reject the request if it did not match the nonce from that header
     * or if the time-stamp value is not recent enough. In this way the
     * server can limit the time of the nonce's validity. The inclusion of
     * the ETag prevents a replay request for an updated version of the
     * resource.  (Note: including the IP address of the client in the
     * nonce would appear to offer the server the ability to limit the
     * reuse of the nonce to the same client that originally got it.
     * However, that would break proxy farms, where requests from a single
     * user often go through different proxies in the farm. Also, IP
     * address spoofing is not that hard.)
     * <p/>
     * An implementation might choose not to accept a previously used
     * nonce or a previously used digest, in order to protect against a
     * replay attack. Or, an implementation might choose to use one-time
     * nonces or digests for POST or PUT requests and a time-stamp for GET
     * requests.  For more details on the issues involved see section 4.
     * of this document.  The nonce is opaque to the client.
     *
     * @return
     */
    private static String getNonce() {
        return "dcd98b7102dd2f0e8b11d0f600bfb0c093";
    }

    public static void fillCertCredentials(Callback[] callbacks, X509Certificate[] certificates) {
        for (Callback callback : callbacks) {
            if (callback instanceof CertificatesCallback) {
                CertificatesCallback cc = (CertificatesCallback) callback;
                cc.setCertificates(certificates);
                break;
            }
        }
    }
}
