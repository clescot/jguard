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
package net.sf.jguard.core.authentication.callbackhandler;

import net.sf.jguard.core.authentication.callbacks.AsynchronousCallbackException;
import net.sf.jguard.core.authentication.callbacks.AuthenticationSchemeHandlerCallback;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.Configuration;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.*;

/**
 * the <i>keystone</i> of interactions between loginModules (the JAAS authentication doFilter),
 * {@link net.sf.jguard.core.technology.Scopes} implementation and its {@link AuthenticationSchemeHandler}s.
 * To support a new <i>communication technology</i>, you require to extends this class, and the related
 * {@link AuthenticationSchemeHandler}s.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public abstract class JGuardCallbackHandler<Req, Res> implements CallbackHandler {

    private static final Logger logger = LoggerFactory.getLogger(JGuardCallbackHandler.class.getName());
    private Collection<AuthenticationSchemeHandler<Req, Res>> registeredAuthenticationSchemeHandlers = null;
    private Request<Req> request;
    private Response<Res> response;
    private Set<AuthenticationSchemeHandler<Req, Res>> usedAuthenticationSchemeHandlers = new HashSet<AuthenticationSchemeHandler<Req, Res>>();


    public JGuardCallbackHandler(Request<Req> request,
                                 Response<Res> response,
                                 Collection<AuthenticationSchemeHandler<Req, Res>> registeredAuthenticationSchemeHandlers) {
        this.request = request;
        this.response = response;
        this.registeredAuthenticationSchemeHandlers = registeredAuthenticationSchemeHandlers;
        if (null == registeredAuthenticationSchemeHandlers || registeredAuthenticationSchemeHandlers.size() == 0) {
            throw new IllegalArgumentException("no registeredAuthenticationSchemeHandlers are registered ");
        }
    }


    private Collection<Class> getCallbacksTypes(List<Callback> cbks) {
        Set<Class> types = new HashSet<Class>();
        for (Callback cbk : cbks) {
            types.add(cbk.getClass());
        }
        return types;
    }

    /**
     * choice of the Authentication Scheme is done by {@link LoginModule}s executed according to the {@link Configuration}.
     * Interactions between multiple loginmodules, to choose which authentication scheme must be encountered
     * among multiple ones, is possible. Each Authentication Scheme is implemented with a loginModule, and its related {@link AuthenticationSchemeHandler}
     * implementation. each {@link AuthenticationSchemeHandler}s are registered in the {@link net.sf.jguard.core.technology.Scopes} implementation.
     * Correlation between a loginModule and an AuthentitcationSchemeHandler is expressed with specific callbacks.
     * this method implements this correlation.
     *
     * @param authenticationSchemeHandlers
     * @param callbacks
     * @return
     */
    private AuthenticationSchemeHandler<Req, Res> getAuthenticationSchemeHandler(Collection<AuthenticationSchemeHandler<Req, Res>> authenticationSchemeHandlers, List<Callback> callbacks) {
        //callbacks required by the current LoginModule (which can contains callbacks not directly related to authenticationSchemeHandler)
        Collection<Class> requiredCallbackTypes = getCallbacksTypes(callbacks);
        for (AuthenticationSchemeHandler<Req, Res> authSchemeHandler : authenticationSchemeHandlers) {
            //callbacks which can be filled by the current AuthenticationSchemeHandler
            Collection<Class<? extends Callback>> callbackTypes = authSchemeHandler.getCallbackTypes();
            //if all callbacks used by the AuthenticationSchemeHandler are present in the callbacks asked by loginmodule
            //we use this authenticationSchemehandler
            if (requiredCallbackTypes.containsAll(callbackTypes)) {
                //callbacks types identify which authenticationSchemeHandler is required 
                //among multiple ones registered in the Scopes and contained in the CallbackHandler
                return authSchemeHandler;
            }

        }

        return null;
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        List<Callback> callbackList = Arrays.asList(callbacks);

        //we select among available authenticationSchemeHandler, and with the supported callbacks requirement,
        //the best authenticationSchemeHandler
        AuthenticationSchemeHandler<Req, Res> authenticationSchemeHandler = getAuthenticationSchemeHandler(registeredAuthenticationSchemeHandlers, callbackList);
        usedAuthenticationSchemeHandlers.add(authenticationSchemeHandler);
        //handle method is called multiple times by loginModules
        //some LoginModules does not put in place any authenticationSchemeHandler
        if (authenticationSchemeHandler == null) {
            return;
        }

        //we set the AuthenticationSchemeHandlerCallback
        for (Callback callback : callbacks) {
            if (callback instanceof AuthenticationSchemeHandlerCallback) {
                AuthenticationSchemeHandlerCallback cbk = (AuthenticationSchemeHandlerCallback) callback;
                cbk.setAuthenticationSchemeHandlerName(authenticationSchemeHandler.getName());
                break;
            }
        }

        if (!authenticationSchemeHandler.answerToChallenge(request, response)
                && authenticationSchemeHandler.challengeNeeded(request, response)) {
            //user has not yet tried to answer to an authentication challenge
            //and we need some authentication informations
            //we build a new challenge in response
            authenticationSchemeHandler.buildChallenge(request, response);

            if (isAsynchronous()) {
                throw new AsynchronousCallbackException(null, authenticationSchemeHandler.getName());
            }
        }

        //user answer to an authentication challenge, so we grab required callbacks
        authenticationSchemeHandler.handleSchemeCallbacks(request, response, callbacks);
    }

    /**
     * define if the communication between client and server is non-blocking (return <b>true</b>) or blocking (return <b>false</b>).
     *
     * @return
     */
    protected abstract boolean isAsynchronous();


    /**
     * propagate to each authenticationSchemeHandler the authenticationSucceed Event.
     *
     * @param subject
     * @param request
     * @param response
     */
    public void authenticationSucceed(Subject subject, Request<Req> request, Response<Res> response) {
        for (AuthenticationSchemeHandler<Req, Res> schemeHandler : usedAuthenticationSchemeHandlers) {
            schemeHandler.authenticationSucceed(subject, request, response);
        }
    }

    /**
     * propagate to each authenticationSchemeHandler the authenticationFailed event.
     *
     * @param request
     * @param response
     */
    public void authenticationFailed(Request<Req> request, Response<Res> response) {
        for (AuthenticationSchemeHandler<Req, Res> schemeHandler : usedAuthenticationSchemeHandlers) {
            schemeHandler.authenticationFailed(request, response);
        }
    }

}
