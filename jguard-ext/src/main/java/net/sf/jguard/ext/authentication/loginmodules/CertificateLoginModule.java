/*
 jGuard is a security framework based on top of jaas (java authentication and authorization security).
 it is written for web applications, to resolve simply, access control problems.
 version $Name$
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
package net.sf.jguard.ext.authentication.loginmodules;

import net.sf.jguard.core.authentication.callbacks.CertificatesCallback;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.loginmodules.UserLoginModule;
import net.sf.jguard.ext.SecurityConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.lang.reflect.Array;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Base class for LoginModules related to certificate.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @see CRLLoginModule
 * @see OCSPLoginModule
 * @since 1.0.0
 */
public abstract class CertificateLoginModule extends UserLoginModule {


    private static final Logger logger = LoggerFactory.getLogger(CertificateLoginModule.class.getName());
    protected Subject subject;
    protected boolean loginOK = true;
    protected X509Certificate[] certChainToCheck;
    protected CallbackHandler callbackHandler;

    /**
     * @see javax.security.auth.spi.LoginModule#abort()
     */
    public boolean abort() throws LoginException {
        if (subject != null) {
            subject.getPrincipals().clear();
            subject.getPrivateCredentials().clear();
            subject.getPublicCredentials().clear();
        }
        return true;
    }

    public boolean commit() throws LoginException {
        if (loginOK) {
            return certificateCommit();
        } else {
            return false;
        }
    }


    /**
     * @see javax.security.auth.spi.LoginModule#logout()
     */
    public boolean logout() throws LoginException {
        subject.getPrincipals().clear();
        subject.getPublicCredentials().clear();
        subject.getPrivateCredentials().clear();
        return true;
    }


    protected boolean certificateCommit() throws LoginException {
        Set publicCredentials = this.subject.getPublicCredentials();
        List certs = Arrays.asList(this.certChainToCheck);
        //we only use the first certificate which is the one assigned to user
        X509Certificate cert = (X509Certificate) certs.get(0);
        subject.getPrincipals().add(cert.getSubjectX500Principal());


        if (cert.getSubjectUniqueID() != null) {
            JGuardCredential credential1 = new JGuardCredential(SecurityConstants.UNIQUE_ID, cert.getSubjectUniqueID());
            publicCredentials.add(credential1);
        }

        Collection altNames = null;
        try {
            altNames = cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            logger.error(" certificate cannot be parsed ");
            //alternativeNames must be valid unless they don't exist
            throw new LoginException(e.getMessage());
        }
        if (altNames == null) {
            return true;
        }
        int count = 0;
        //populate alternativeNames
        for (Object altName : altNames) {
            List extensionEntry = (List) altName;
            Integer nameType = (Integer) extensionEntry.get(0);
            Object name = extensionEntry.get(1);
            byte[] nameAsBytes = null;
            JGuardCredential credential = null;
            if (name instanceof Array) {
                nameAsBytes = (byte[]) name;
            }
            if (nameAsBytes != null) {
                credential = new JGuardCredential(SecurityConstants.ALTERNATIVE_NAME + "#" + count, nameType + "#" + new String(nameAsBytes));
            } else {
                credential = new JGuardCredential(SecurityConstants.ALTERNATIVE_NAME + "#" + count, nameType + "#" + name);
            }
            publicCredentials.add(credential);
            count++;
        }

        return true;
    }

    protected List<Callback> getCallbacks() {
        List<Callback> cbcks = new ArrayList<Callback>();
        cbcks.add(new CertificatesCallback());
        return cbcks;
    }

    public boolean login() throws LoginException {
        super.login();
        if (callbackHandler == null) {
            loginOK = false;
            throw new LoginException("there is no CallbackHandler to authenticate the user");
        }

        try {
            callbackHandler.handle(callbacks);
        } catch (IOException e1) {
            logger.error(" IOException when we handle callbacks with callback " + callbackHandler.getClass().getName(), e1);
        } catch (UnsupportedCallbackException e1) {
            logger.error(" one callback type is not supported ", e1);
        }
        certChainToCheck = ((CertificatesCallback) callbacks[0]).getCertificates();
        if (certChainToCheck == null || certChainToCheck.length == 0) {
            loginOK = false;
            //no certificates can be checked so we inactivate this loginmodule
            return false;
        }
        X509Certificate[] certChainToCheck = ((CertificatesCallback) callbacks[2]).getCertificates();
        if (certChainToCheck != null) {
            //in this case (CLIENT-CERT scheme), password is null
            //and login is given by the Distinguished name of the Subject from the user certificate
            //there is no need to grab it from an http FORM
            login = certChainToCheck[0].getSubjectX500Principal().getName();
            if (debug) {
                logger.debug(" login used in the certificate =" + login);
            }
            skipPasswordCheck = true;
        }
        return true;
    }
}
