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

package net.sf.jguard.core.authentication.schemes;

import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.spi.LoginModule;
import java.security.PermissionCollection;
import java.util.Collection;

/**
 * represent a part of the CallbackHandler.
 * it represents transcription in the underlying technology of the AuthenticationScheme needs.
 * it
 * Note that multiple exchanges can be encountered between client and server to establish
 * a securized communication. These exchanges are <b>NOT</b> decided mainly by any {@link AuthenticationSchemeHandler}
 * implementations but by underlying {@link LoginModule}s which enforce an Authentication Scheme.
 * AuthenticationSchemeHandler only help loginModules to communicate with the client
 * through its supported underlying technology.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public interface AuthenticationSchemeHandler<Req extends Request, Res extends Response> {


    /**
     * unique name of the Authentication Scheme.
     *
     * @return
     */
    String getName();


    /**
     * return callbacks classes supported by this AuthenticationSchemeHandler, and needed by LoginModules to authenticate the client.
     *
     * @return
     */
    Collection<Class<? extends Callback>> getCallbackTypes();


    /**
     * evaluate if the user <b>tries</b> to answer to the authentication challenge.
     *
     * @param request
     * @param response
     * @return
     */
    boolean answerToChallenge(Req request, Res response);


    /**
     * when the user isn't authenticated, and doesn't answer to a challenge, does the authenticationSchemeHandler
     * need to build a challenge to collect some informations?
     * sometimes, it is not needed, like with an audit activity.
     *
     * @param request
     * @param response
     * @return
     */
    boolean challengeNeeded(Req request, Res response);


    /**
     * create a challenge in the underlying technology way.
     *
     * @param request
     * @param response
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    void buildChallenge(Req request, Res response);


    /**
     * grab informations in the underlying technology and convert them into callbacks.
     *
     * @param request
     * @param response
     * @param callbacks
     * @throws UnsupportedCallbackException
     */
    void handleSchemeCallbacks(Req request, Res response, Callback[] callbacks) throws UnsupportedCallbackException;


    /**
     * return permissions needed by this authenticationSchemeHandler.
     * without these permissions granted to user,the user cannot enforce the
     * authentication Scheme.
     *
     * @return permissions needed by this authenticationScheme
     */
    PermissionCollection getGrantedPermissions();

    /**
     * translate into the underlying technology the overall authentication success.
     *
     * @param subject
     * @param request
     * @param response
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    void authenticationSucceed(Subject subject, Req request, Res response);

    /**
     * translate into the underlying technology the overall authentication failure.
     *
     * @param request
     * @param response
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    void authenticationFailed(Req request, Res response);


}
