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

import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.security.PermissionCollection;
import java.util.ArrayList;
import java.util.Collection;

/**
 * permits to set Login and password directly. It follows the architecture design,
 * but permits to hook it.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @since 2.0
 */
public abstract class HookFormSchemeHandler<Req extends Request, Res extends Response> implements AuthenticationSchemeHandler<Req, Res> {
    private static final String HOOK = "HOOK";

    public HookFormSchemeHandler(Collection<Callback> callbacks) {
        this.callbacks = callbacks;
    }

    private Collection<Callback> callbacks;

    public String getName() {
        return HOOK;
    }


    public boolean impliesChallenge() {
        return true;
    }

    public void buildChallenge(Req request, Res response) {
        throw new UnsupportedOperationException("Not supported yet.");
    }


    public void authenticationSucceed(Subject subject, Req request, Res response) {

    }

    public void authenticationFailed(Req request, Res response) {

    }

    public Collection<Class<? extends Callback>> getCallbackTypes() {
        Collection<Class<? extends Callback>> callbackTypes = new ArrayList<Class<? extends Callback>>();
        callbackTypes.add(NameCallback.class);
        callbackTypes.add(PasswordCallback.class);
        return callbackTypes;
    }


    public PermissionCollection getGrantedPermissions() {
        return new JGPositivePermissionCollection();
    }

    public boolean answerToChallenge(Req request, Res response) {
        return true;
    }


    /**
     * grab callback values needed.
     *
     * @param request
     * @param response
     * @param callbacksToReplace
     * @throws javax.security.auth.callback.UnsupportedCallbackException
     *
     */
    public void handleSchemeCallbacks(Req request, Res response, Callback[] callbacksToReplace) throws UnsupportedCallbackException {
        for (int i = 0; i < callbacksToReplace.length; i++) {
            Callback replacedCallback = replaceCallback(callbacksToReplace[i]);
            callbacksToReplace[i] = replacedCallback;
        }
    }


    /**
     * we try to replace the needed callback by
     * the one provided in the constructor, if their class are
     * equals. otherwise, we return the original one provided in argument.
     *
     * @param callbackToReplace
     * @return
     */
    private Callback replaceCallback(Callback callbackToReplace) {
        Class clazz = callbackToReplace.getClass();
        for (Callback cb : callbacks) {
            if (cb.getClass().equals(clazz)) {
                return cb;
            }
        }
        return callbackToReplace;
    }

}
