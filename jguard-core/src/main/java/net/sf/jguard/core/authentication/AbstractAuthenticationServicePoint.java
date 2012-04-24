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

package net.sf.jguard.core.authentication;

import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.exception.AuthenticationContinueException;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.loginmodules.AuthenticationChallengeException;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.technology.ImpersonationScopes;
import net.sf.jguard.core.technology.Scopes;
import net.sf.jguard.core.util.SubjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.util.Collection;


/**
 * Authenticate a user in an application with a specific {@link net.sf.jguard.core.technology.Scopes}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @since 2 .0
 */
public abstract class AbstractAuthenticationServicePoint<Req, Res> implements AuthenticationServicePoint<Req, Res> {

    private static final Logger logger = LoggerFactory.getLogger(AbstractAuthenticationServicePoint.class.getName());

    private Configuration configuration;
    private Configuration guestConfiguration;
    private Collection<AuthenticationSchemeHandler<Req, Res>> authenticationSchemeHandlers;
    private String applicationName;
    private Scopes scopes;
    private JGuardCallbackHandler guestCallbackHandler;
    private static final String AUTHENTICATION_SUCCEEDED = "authenticationSucceededDuringThisRequest";
    private static final String LOGIN_EXCEPTION_CLASS = "LoginExceptionClass";
    private static final String LOGIN_EXCEPTION_MESSAGE = "LoginExceptionMessage";
    private static final String REGISTRATION_DONE = "registrationDone";

    public AbstractAuthenticationServicePoint(Configuration configuration,
                                              Configuration guestConfiguration,
                                              Collection<AuthenticationSchemeHandler<Req, Res>> authenticationSchemeHandlers,
                                              String applicationName,
                                              Scopes scopes,
                                              JGuardCallbackHandler guestCallbackHandler) {
        this.configuration = configuration;
        this.guestConfiguration = guestConfiguration;
        this.authenticationSchemeHandlers = authenticationSchemeHandlers;
        this.applicationName = applicationName;
        this.scopes = scopes;
        this.guestCallbackHandler = guestCallbackHandler;
    }


    public LoginContextWrapper authenticate(Request<Req> request,
                                            Response<Res> response,
                                            JGuardCallbackHandler<Req, Res> callbackHandler) {
        return authenticate(request, response, configuration, scopes, callbackHandler);
    }


    private LoginContextWrapper authenticate(Request<Req> request,
                                             Response<Res> response,
                                             Configuration configuration,
                                             Scopes scopes,
                                             JGuardCallbackHandler<Req, Res> callbackHandler) throws AuthenticationException {
        scopes.setRequestAttribute(REGISTRATION_DONE, Boolean.FALSE);

        LoginContextWrapper loginContextWrapper = null;
        try {
            //we grab the wrapper object which link the user via its session with authentication
            loginContextWrapper = getLoginContextWrapper(scopes);

            //we use the wrapper object bound to user with the dedicated object(callabckHandler)
            //to communicate with him to authenticate

            loginContextWrapper.login(callbackHandler, configuration);
            authenticationSucceed(loginContextWrapper);


            //propagate the authentication success
            callbackHandler.authenticationSucceed(loginContextWrapper.getSubject(), request, response);
            loginContextWrapper.setStatus(AuthenticationStatus.SUCCESS);
            return loginContextWrapper;

        } catch (AuthenticationContinueException ace) {
            //the current AuthenticationScheme needs multiple roundtrips
            logger.debug("authentication is not yet complete. a new exchange between client and server is required " + ace.getMessage());
            loginContextWrapper.setStatus(AuthenticationStatus.CONTINUE);
            return loginContextWrapper;
        } catch (AuthenticationChallengeException ace) {
            //the callbackHandle handle this case. we only need here to go back the call to the user
            logger.debug("authentication challenge built. a new exchange between client and server is required " + ace.getMessage());
            loginContextWrapper.setStatus(AuthenticationStatus.FAILURE);
            return loginContextWrapper;

        } catch (LoginException e) {

            logger.debug("authentication failed " + e.getMessage(), e);
            String messageError = e.getLocalizedMessage();
            //we store in the user' session the reason the authentication failed
            scopes.setRequestAttribute(LOGIN_EXCEPTION_MESSAGE, messageError);
            scopes.setRequestAttribute(LOGIN_EXCEPTION_CLASS, e.getClass());

            callbackHandler.authenticationFailed(request, response);
            loginContextWrapper.setStatus(AuthenticationStatus.FAILURE);
            return loginContextWrapper;

        }
    }

    /**
     * method called when authentication succeed. it can be overriden by subclasses,
     * for, as an example, do some manipulation on Stateful sessions.
     *
     * @param loginContextWrapper
     */
    protected void authenticationSucceed(LoginContextWrapper loginContextWrapper) {
    }


    public LoginContextWrapper impersonateAsGuest(Request<Req> request,
                                                  Response<Res> response,
                                                  ImpersonationScopes impersonationScopes) {
        //we put the guest Configuration to use a GuestAppConfigurationFilter, through a GuestConfiguration wrapper,
        //to not use loginModules which does not inherit from UserLoginModule,
        //and add a SKIP_CREDENTIAL_CHECK option to subclasses of UserLoginModules
        return authenticate(request, response, guestConfiguration, impersonationScopes, guestCallbackHandler);
    }

    public boolean answerToChallenge(Request<Req> request, Response<Res> response) {
        for (AuthenticationSchemeHandler<Req, Res> handler : authenticationSchemeHandlers) {
            boolean answerToChallenge = handler.answerToChallenge(request, response);
            if (answerToChallenge) {
                return true;
            }
        }

        return false;
    }

    protected Collection<AuthenticationSchemeHandler<Req, Res>> getAuthenticationSchemeHandlers() {
        return authenticationSchemeHandlers;
    }


    /**
     * return the <i>current</i> {@link Subject}:
     * this method is looking for from the local scope to the global scope.
     * - firstly, looking for the AccessControlContext bound to the Thread.
     * - if not present, and if the scopes implements StatefulScopes,
     * looking for the Subject present in the session.
     * - if not present or not stateful, looking for the Guest Subject present in the application scope.
     *
     * @return current Subject
     */
    public Subject getCurrentSubject() {
        Subject subject = getSubjectInAccessControlContext();
        if (subject == null) {
            subject = (Subject) scopes.getApplicationAttribute(SubjectUtils.GUEST_SUBJECT);
        }
        return subject;

    }

    /**
     * grab the authenticated PersistedSubject in the execution stack.
     *
     * @return authenticated PersistedSubject or null if user is not authenticated
     * @throws SecurityException the caller does not have the permission to call the subject
     */
    protected static Subject getSubjectInAccessControlContext() {
        AccessControlContext acc = AccessController.getContext();
        if (acc == null) {
            //acc== null signifies System code,
            //so, no Subject is bound to it
            return null;
        }
        return Subject.getSubject(acc);
    }

    /**
     * create a new LoginContextWrapperImpl .
     * Note that each LoginContextWrapperImpl instance is related to a Subject,
     * so different LoginContextWrapperImpl coexist.It can be done because
     * Scopes is different among users.
     *
     * @param scopes
     * @return AuthenticationUtils
     */
    protected LoginContextWrapper getLoginContextWrapper(Scopes scopes) {

        if (scopes == null) {
            throw new IllegalArgumentException("scopes is null");
        }
        return new LoginContextWrapperImpl(applicationName);
    }


    public boolean authenticationSucceededDuringThisRequest(Request<Req> request, Response<Res> response) {
        String authenticationSucceeded = (String) scopes.getRequestAttribute(AUTHENTICATION_SUCCEEDED);
        return null != authenticationSucceeded && Boolean.parseBoolean(authenticationSucceeded);
    }

}
