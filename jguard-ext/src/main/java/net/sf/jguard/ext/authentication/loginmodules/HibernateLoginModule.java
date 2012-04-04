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

import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.loginmodules.UserLoginModule;
import net.sf.jguard.core.authentication.loginmodules.UserNamePasswordLoginModule;
import net.sf.jguard.core.util.SubjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.CredentialException;
import javax.security.auth.login.CredentialNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Map;
import java.util.Set;

/**
 * Hibernate implementation used to authenticate the user.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HibernateLoginModule extends UserNamePasswordLoginModule implements LoginModule {
    private static final Logger logger = LoggerFactory.getLogger(HibernateLoginModule.class.getName());

    @Override
    public void initialize(Subject subj, CallbackHandler cbk, Map sState, Map opts) {
        try {
            super.initialize(subj, cbk, sState, opts);


            Set<Subject> users = authenticationManager.getUsers();
            if (users == null || users.size() == 0) {
                throw new IllegalStateException(" there are nos users present in the database ");
            }
        } catch (AuthenticationException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }


    @Override
    public boolean login() throws LoginException {
        super.login();
        Subject subjectFound = authenticationManager.findUser(login);
        if (subjectFound == null) {
            logger.info(" user with login=" + login + " does not exists");
            throw new CredentialNotFoundException(XmlLoginModule.LOGIN_ERROR);
        }
        if (!skipPasswordCheck || password != null) {

            JGuardCredential passwordCredential = new JGuardCredential(authenticationManager.getCredentialPassword(), new String(password));

            Set privateCredentialsTemp = subjectFound.getPrivateCredentials();
            if ((privateCredentialsTemp.contains(passwordCredential)) || skipPasswordCheck) {

                //we store in the loginModule instance principals and credentials but
                //assign to the subject only in th ecommit phase
                globalPrincipals = subjectFound.getPrincipals();
                globalPrivateCredentials = subjectFound.getPrivateCredentials();
                String active = SubjectUtils.getCredentialValueAsString(subjectFound, false, "active");
                if (!active.equals("true")) {
                    throw new FailedLoginException(UserLoginModule.USER_INACTIVE);
                }
                globalPublicCredentials = subjectFound.getPublicCredentials();
                //password match
                return true;
            } else {
                //password does not match
                throw new CredentialException(UserLoginModule.LOGIN_ERROR);
            }

        }
        //skipPasswordCheck is true
        return true;
    }


}
