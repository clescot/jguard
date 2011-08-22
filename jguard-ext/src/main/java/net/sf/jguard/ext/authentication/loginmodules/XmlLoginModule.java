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

import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.loginmodules.UserNamePasswordLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.CredentialException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;


/**
 * LoginModule configured by the <i>jGuardUsersPrincipals</i> XML file.<br>
 * In webapp environement using JGuardConfiguration, the AuthenticationManager related to the LoginModule is created by AccessFilter.<br>
 * In non-JGuardConfiguration environement, the LoginModule must create its AuthenticationManager, and applicationName
 * is required for this creation.<br>
 * In order to retreive the application name, XmlLoginModule uses the following ways :
 * <ul>
 * <li>trough vm arg : <code>net.sf.jguard.application.name</code> VM arg</li>
 * <li>trough vm arg : <code>com.sun.management.jmxremote.login.config</code>
 * if you have already defined this property because you use JMX.
 * Do not set application name through this property if you are not using JMX !</li>
 * </ul>
 * If no applicationName is explicitly passed to the application, default application name "other" is used.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @see LoginModule
 */
public class XmlLoginModule extends UserNamePasswordLoginModule implements LoginModule {


    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(XmlLoginModule.class.getName());

    private Set<Subject> users;
    private static final String NET_SF_JGUARD_APPLICATION_NAME = "net.sf.jguard.application.name";
    private static final String COM_SUN_MANAGEMENT_JMXREMOTE_LOGIN_CONFIG = "com.sun.management.jmxremote.login.config";

    /**
     * initialize the loginModule.
     *
     * @param subject
     * @param callbackHandler
     * @param sharedState
     * @param options
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState,
                           Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);

        try {
            users = authenticationManager.getUsers();
            if(null==users||users.size()==0){
                throw new IllegalStateException("users are null or empty");
            }
        } catch (AuthenticationException e) {
            logger.error(" initialize ", e);
        }
    }

    /**
     * Authenticate the user.
     *
     * @return true if the user is authenticated, false otherwise.
     * @throws javax.security.auth.login.FailedLoginException
     *                        authentication fails
     * @throws LoginException if this <code>LoginModule</code> is unable to perform the authentication.
     */
    @Override
    public boolean login() throws LoginException {
        super.login();

        JGuardCredential loginCredential = new JGuardCredential(authenticationManager.getCredentialId(), login);

        JGuardCredential passwordCredential = new JGuardCredential(authenticationManager.getCredentialPassword(), new String(password));

        Subject user;
        Iterator it = users.iterator();
        boolean authenticationSucceed = false;

        while (it.hasNext()) {
            user = (Subject) it.next();
            Set privateCredentialsTemp = user.getPrivateCredentials(JGuardCredential.class);
            Set publicCredentialsTemp = user.getPublicCredentials(JGuardCredential.class);
            if (privateCredentialsTemp.contains(loginCredential)) {
                if ((privateCredentialsTemp.contains(passwordCredential)) || skipPasswordCheck) {

                    //authentication succeed because one user has got cred1 and cred2
                    globalPrincipals = user.getPrincipals();
                    globalPrivateCredentials = user.getPrivateCredentials();
                    globalPublicCredentials = user.getPublicCredentials();
                    authenticationSucceed = true;
                }
                break;
            }
        }

        if (!authenticationSucceed) {
            loginOK = false;
            throw new CredentialException(XmlLoginModule.LOGIN_ERROR);
        }

        return true;
    }


}
