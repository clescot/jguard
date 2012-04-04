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

import net.sf.jguard.core.authentication.callbacks.InetAddressCallback;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.loginmodules.UserLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.LanguageCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Audit authentication success, failures, and logout events.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class AuditLoginModule extends UserLoginModule implements LoginModule {

    private static final Logger logger = LoggerFactory.getLogger(AuditLoginModule.class.getName());
    private InetAddressCallback inetCbk;
    private NameCallback nameCallback;
    private Locale locale;
    private LanguageCallback languageCallback;

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
    }

    public boolean login() throws LoginException {
        super.login();
        inetCbk = (InetAddressCallback) callbacks[0];
        nameCallback = (NameCallback) callbacks[1];
        languageCallback = (LanguageCallback) callbacks[2];
        if (languageCallback.getLocale() != null) {
            locale = languageCallback.getLocale();
        }
        //if locale in languageCallback is null,
        //the default one is set with the login method in the super class, which calls
        //getCallbacks method in this class which set the default locale

        return true;
    }

    public boolean commit() throws LoginException {
        return logAuthentication(true);

    }

    public boolean abort() throws LoginException {
        return logAuthentication(false);
    }

    @Override
    protected List<Callback> getCallbacks() {
        inetCbk = new InetAddressCallback();
        nameCallback = new NameCallback(" ");
        locale = Locale.getDefault();
        languageCallback = new LanguageCallback();
        List<Callback> callbacks = new ArrayList<Callback>();
        callbacks.add(inetCbk);
        callbacks.add(nameCallback);
        callbacks.add(languageCallback);
        return callbacks;
    }

    public boolean logout() throws LoginException {

        try {
            long now = System.currentTimeMillis();
            persistUserLogoutAttempt(nameCallback.getName(), inetCbk.getHostAdress(), inetCbk.getHostName(), now);
            logger.info("user from Host adress=" + inetCbk.getHostAdress() + " bound to host name=" + inetCbk.getHostName() + " has logoff" + " timeStamp=" + now + " locale=" + locale.getDisplayName());
        } catch (AuthenticationException ex) {
            logger.error(ex.getMessage(), ex);
            return false;
        }
        return true;
    }

    private void persistUserLogoutAttempt(String name, String hostAdress, String hostName, long now) {

    }

    private boolean logAuthentication(boolean authenticationResult) throws LoginException {

        try {
            long now = System.currentTimeMillis();
            persistUserLoginAttempt(nameCallback.getName(), inetCbk.getHostAdress(), inetCbk.getHostName(), authenticationResult, now);
            logger.info("user from Host adress=" + inetCbk.getHostAdress() + " bound to host name=" + inetCbk.getHostName() + " has tried to authenticate. boolean result =" + authenticationResult + " timeStamp=" + now + " locale=" + locale.getDisplayName());
            return true;
        } catch (AuthenticationException ex) {
            logger.error(ex.getMessage(), ex);
            return false;
        }
    }

    private void persistUserLoginAttempt(String name, String hostAdress, String hostName, boolean authenticationResult, long now) {

    }

}
