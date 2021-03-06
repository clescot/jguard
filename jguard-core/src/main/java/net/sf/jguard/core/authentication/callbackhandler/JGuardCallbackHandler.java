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
package net.sf.jguard.core.authentication.callbackhandler;

import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
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
 * the <i>keystone</i> of interactions between loginModules  implementation and its {@link AuthenticationSchemeHandler}s.
 * To support a new <i>communication technology</i>, you require to extends this class, and the related
 * {@link AuthenticationSchemeHandler}s.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class JGuardCallbackHandler<Req extends Request, Res extends Response> implements CallbackHandler {

    private static final Logger logger = LoggerFactory.getLogger(JGuardCallbackHandler.class.getName());
    protected Collection<AuthenticationSchemeHandler<Req, Res>> registeredAuthenticationSchemeHandlers = null;


    protected Req request;
    protected Res response;
    private Set<AuthenticationSchemeHandler<Req, Res>> usedAuthenticationSchemeHandlers = new HashSet<AuthenticationSchemeHandler<Req, Res>>();


    public JGuardCallbackHandler(Req request,
                                 Res response,
                                 Collection<AuthenticationSchemeHandler<Req, Res>> registeredAuthenticationSchemeHandlers) {
        this.request = request;
        this.response = response;
        this.registeredAuthenticationSchemeHandlers = registeredAuthenticationSchemeHandlers;
        if (null == registeredAuthenticationSchemeHandlers || registeredAuthenticationSchemeHandlers.size() == 0) {
            throw new IllegalArgumentException("no registeredAuthenticationSchemeHandlers are registered ");
        }
    }


    private Collection<Class> getCallbacksClasses(List<Callback> cbks) {
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
     * implementation. each {@link AuthenticationSchemeHandler}s are registered.
     * Correlation between a loginModule and an AuthenticationSchemeHandler is expressed with specific callbacks.
     * this method implements this correlation.
     *
     * @param authenticationSchemeHandlers
     * @param callbacks
     * @return
     */
    private AuthenticationSchemeHandler<Req, Res> getAuthenticationSchemeHandler(Collection<AuthenticationSchemeHandler<Req, Res>> authenticationSchemeHandlers, List<Callback> callbacks) {
        //callbacks required by the current LoginModule (which can contains callbacks not directly related to authenticationSchemeHandler)
        Collection<Class> requiredCallbackTypes = getCallbacksClasses(callbacks);
        for (AuthenticationSchemeHandler<Req, Res> authSchemeHandler : authenticationSchemeHandlers) {
            //callbacks which can be filled by the current AuthenticationSchemeHandler
            Collection<Class<? extends Callback>> callbackTypes = Lists.newArrayList(authSchemeHandler.getCallbackTypes());
            callbackTypes.add(AuthenticationSchemeHandlerCallback.class);
            //if all callbacks used by the AuthenticationSchemeHandler are present in the callbacks asked by loginmodule
            //we use this authenticationSchemehandler
            if (!requiredCallbackTypes.isEmpty() && callbackTypes.containsAll(requiredCallbackTypes)) {
                //callbacks types identify which authenticationSchemeHandler is required 
                //among multiple ones registered in the Scopes and contained in the CallbackHandler
                return authSchemeHandler;
            }

        }

        logger.warn("no authenticationSchemeHandler can handle " + Joiner.on(',').join(callbacks));
        return null;
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        AuthenticationSchemeHandler<Req, Res> authenticationSchemeHandler = prepareCallbackHandler(callbacks);
        if (authenticationSchemeHandler == null) return;

        handle(callbacks, authenticationSchemeHandler);


    }

    protected void handle(Callback[] callbacks, AuthenticationSchemeHandler<Req, Res> authenticationSchemeHandler) throws UnsupportedCallbackException {
        //user answer to an authentication challenge, so we grab required callbacks
        authenticationSchemeHandler.handleSchemeCallbacks(request, response, callbacks);


    }

    private AuthenticationSchemeHandler<Req, Res> prepareCallbackHandler(Callback[] callbacks) {
        List<Callback> callbackList = Arrays.asList(callbacks);

        //we select among available authenticationSchemeHandlers, and with the supported callbacks requirement,
        //the best authenticationSchemeHandler
        AuthenticationSchemeHandler<Req, Res> authenticationSchemeHandler = getAuthenticationSchemeHandler(registeredAuthenticationSchemeHandlers, callbackList);
        //handle method is called multiple times by loginModules
        //some LoginModules does not put in place any authenticationSchemeHandler
        if (authenticationSchemeHandler == null) {
            return null;
        }
        usedAuthenticationSchemeHandlers.add(authenticationSchemeHandler);

        populateAuthenticationSchemeHandlerCallbackIfPresent(callbacks, authenticationSchemeHandler);
        return authenticationSchemeHandler;
    }

    private void populateAuthenticationSchemeHandlerCallbackIfPresent(Callback[] callbacks, AuthenticationSchemeHandler<Req, Res> authenticationSchemeHandler) {
        //we set the AuthenticationSchemeHandlerCallback
        for (Callback callback : callbacks) {
            if (callback instanceof AuthenticationSchemeHandlerCallback) {
                AuthenticationSchemeHandlerCallback cbk = (AuthenticationSchemeHandlerCallback) callback;
                cbk.setAuthenticationSchemeHandlerName(authenticationSchemeHandler.getName());
                break;
            }
        }
    }


    /**
     * propagate to each authenticationSchemeHandler the authenticationSucceed Event.
     *
     * @param subject
     */
    public void authenticationSucceed(Subject subject) {
        for (AuthenticationSchemeHandler<Req, Res> schemeHandler : usedAuthenticationSchemeHandlers) {
            schemeHandler.authenticationSucceed(subject, request, response);
        }
    }

    /**
     * propagate to each authenticationSchemeHandler the authenticationFailed event.
     */
    public void authenticationFailed() {
        for (AuthenticationSchemeHandler<Req, Res> schemeHandler : usedAuthenticationSchemeHandlers) {
            schemeHandler.authenticationFailed(request, response);
        }
    }

    public Req getRequest() {
        return request;
    }

}
