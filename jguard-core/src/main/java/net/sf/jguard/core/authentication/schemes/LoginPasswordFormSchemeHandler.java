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

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.ArrayList;
import java.util.Map;

/**
 * HTTP FORM which requires a login (NameCallback) and a password (PasswordCallback).
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @see NameCallback
 * @see PasswordCallback
 * @since 2.0
 */
public abstract class LoginPasswordFormSchemeHandler<Req extends Request, Res extends Response> extends FORMSchemeHandler<Req, Res> {


    public static final String LOGIN = "login";
    public static final String PASSWORD = "password";
    private static final String LOGIN_PASSWORD_FORM = "Login_Password-FORM";
    private static final String EMPTY_STRING = "";

    @Inject
    public LoginPasswordFormSchemeHandler(Map<String, String> parameters) {
        super(parameters);
        callbackTypes = new ArrayList<Class<? extends Callback>>();
        callbackTypes.add(NameCallback.class);
        callbackTypes.add(PasswordCallback.class);

    }


    public String getName() {
        return LOGIN_PASSWORD_FORM;
    }


    public void handleSchemeCallbacks(Req request, Res response, Callback[] callbacks) throws UnsupportedCallbackException {
        String login = getLogin(request);
        if (null == login || EMPTY_STRING.equals(login)) {
            throw new IllegalArgumentException("login is null or empty");
        }
        String password = getPassword(request);
        if (null == password || EMPTY_STRING.equals(password)) {
            throw new IllegalArgumentException("password is null or empty");
        }
        for (Callback cb : callbacks) {
            if (cb instanceof NameCallback) {
                ((NameCallback) cb).setName(login);
            } else if (cb instanceof PasswordCallback) {
                ((PasswordCallback) cb).setPassword(password.toCharArray());
            }
        }
    }

    /**
     * request must enforce logonProcessPermission (from FormSchemeHandler),
     * and contains a login and a password different from null or an empty string.
     *
     * @param request
     * @param response
     * @return
     */
    public boolean answerToChallenge(Req request, Res response) {
        if (!super.answerToChallenge(request, response)) {
            return false;
        }
        String login = getLogin(request);
        String password = getPassword(request);
        return null != login && !EMPTY_STRING.equals(login) && null != password && !EMPTY_STRING.equals(password);
    }

    protected abstract String getLogin(Req request);

    protected abstract String getPassword(Req request);


}
