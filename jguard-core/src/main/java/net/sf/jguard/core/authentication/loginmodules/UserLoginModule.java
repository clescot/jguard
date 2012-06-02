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
package net.sf.jguard.core.authentication.loginmodules;

import com.google.common.base.Preconditions;
import net.sf.jguard.core.authentication.callbacks.AuthenticationChallengeForCallbackHandlerException;
import net.sf.jguard.core.authentication.callbacks.AuthenticationSchemeHandlerCallback;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.authentication.manager.JGuardAuthenticationManagerMarkups;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * Abstract LoginModule which provides convenient methods for loginmodule
 * involved in grabbing user account informations.
 * subclasses of this loginModule are involved in populating the Subject if authentication succeed.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class UserLoginModule implements LoginModule {

    protected Subject subject;
    private CallbackHandler callbackHandler;
    protected Map sharedState;
    protected Map<String, ?> options;
    protected boolean debug = false;
    private static final Logger logger = LoggerFactory.getLogger(UserLoginModule.class.getName());
    protected String login = null;
    protected char[] password = null;
    protected boolean skipPasswordCheck;
    protected boolean loginOK = true;
    public static final String LOGIN_ERROR = "login.error";
    protected static final String USER_INACTIVE = "user.inactive";
    protected Set<Principal> globalPrincipals;
    protected Set<Object> globalPrivateCredentials;
    protected Set<Object> globalPublicCredentials;
    private String authenticationSchemeHandlerName;
    protected AuthenticationManager authenticationManager;
    protected Callback[] callbacks;
    public static final String SKIP_CREDENTIAL_CHECK = "skipCredentialCheck";
    public final static String AUTHENTICATION_SCHEME_HANDLER_NAME = "authenticationSchemeHandlerName";
    public final static String DEBUG = "debug";

    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState,
                           Map<String, ?> options) {
        Preconditions.checkNotNull(subject, "subject to authenticate in loginModule cannot be 'null'");
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
        if (options != null) {
            debug = Boolean.valueOf((String) options.get(DEBUG));
            skipPasswordCheck = Boolean.valueOf((String) options.get(SKIP_CREDENTIAL_CHECK));
            authenticationManager = (AuthenticationManager) options.get(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel());
            if (authenticationManager == null) {
                throw new IllegalArgumentException("authenticationManager is null : 'options' map must contains an authenticationManager instance bound to the '" + JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel() + "' key");
            }
        } else {
            throw new IllegalArgumentException("options map is null : 'options' map must contains an authenticationManager instance");
        }
        if (callbackHandler == null) {
            throw new IllegalArgumentException("callbackHandler is null");
        }
    }

    /**
     * we ignore the PMD rule for the LoginException class,
     * which unfortunately hide the {@link java.security.GeneralSecurityException} constructor which
     * contains a {@link Throwable} parameter.
     *
     * @return
     * @throws LoginException
     */
    @SuppressWarnings("PMD.PreserveStackTrace")
    public boolean login() throws LoginException {
        if (!skipPasswordCheck) {
            skipPasswordCheck = Boolean.valueOf((String) sharedState.get(SKIP_CREDENTIAL_CHECK));
        }

        List<Callback> cbks = getCallbacks();
        cbks.add(new AuthenticationSchemeHandlerCallback());
        try {
            callbacks = cbks.toArray(new Callback[cbks.size()]);
            callbackHandler.handle(callbacks);

            authenticationSchemeHandlerName = ((AuthenticationSchemeHandlerCallback) getCallback(cbks, AuthenticationSchemeHandlerCallback.class)).getAuthenticationSchemeHandlerName();

        } catch (java.io.IOException ioe) {
            throw new LoginException(ioe.toString());
        } catch (AuthenticationChallengeForCallbackHandlerException cnc) {
            throw new AuthenticationChallengeException(cnc.getMessage());
        } catch (UnsupportedCallbackException uce) {
            throw new LoginException("Callback error : " + uce.getCallback().toString() +
                    " not available to authenticate the user");
        }


        return true;
    }

    /**
     * remove Principals and Private/Public credentials from Subject.
     *
     * @see javax.security.auth.spi.LoginModule#logout()
     */
    public boolean logout() throws LoginException {
        if (subject != null) {
            subject.getPrincipals().clear();
            subject.getPrivateCredentials().clear();
            subject.getPublicCredentials().clear();
        }
        return true;
    }


    /**
     * remove Principals and Public/Private Credentials from Subject.
     *
     * @see javax.security.auth.spi.LoginModule#abort()
     */
    public boolean abort() throws LoginException {
        if (subject != null) {
            subject.getPrincipals().clear();
            subject.getPrivateCredentials().clear();
            subject.getPublicCredentials().clear();
        }
        if (globalPrivateCredentials != null) {
            globalPrivateCredentials.clear();
        }
        if (globalPublicCredentials != null) {
            globalPublicCredentials.clear();
        }
        if (globalPrincipals != null) {
            globalPrincipals.clear();
        }
        return true;
    }

    protected abstract List<Callback> getCallbacks();

    private Callback getCallback(List<Callback> callbacks, Class clazz) {
        for (Callback callback : callbacks) {
            if (clazz.equals(callback.getClass())) {
                return callback;
            }
        }
        return null;
    }


    /**
     * add Principals and Public/Private credentials to Subject.
     *
     * @see javax.security.auth.spi.LoginModule#commit()
     */
    public boolean commit() throws LoginException {
        if (!loginOK) {
            return false;
        }
        if (subject != null) {
            Set<Principal> principals = subject.getPrincipals();
            if (globalPrincipals != null) {
                principals.addAll(globalPrincipals);
            }
            Set<Object> privCredentials = subject.getPrivateCredentials();
            if (globalPrivateCredentials != null) {
                privCredentials.addAll(globalPrivateCredentials);
            }
            Set<Object> pubCredentials = subject.getPublicCredentials();
            if (globalPublicCredentials != null) {
                pubCredentials.addAll(globalPublicCredentials);
            }
            JGuardCredential cred = new JGuardCredential(AUTHENTICATION_SCHEME_HANDLER_NAME, authenticationSchemeHandlerName);
            pubCredentials.add(cred);

        }
        return true;
    }

}
