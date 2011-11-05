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
package net.sf.jguard.jee.lifecycle;

import net.sf.jguard.core.authentication.callbacks.GuestCallbacksProvider;
import net.sf.jguard.ext.authentication.callbacks.CallbackHandlerUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * wrap the ServletRequest object to 'decorate' it to
 * anonymize the user by hiding some request parameters and identifying as GUEST.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class AnonymizerRequestWrapper extends HttpServletRequestWrapper {
    private HttpServletRequest req;
    private String loginField = "login";
    private String passwordField = "password";
    private static final String AUTHORIZATION = "authorization";

    public AnonymizerRequestWrapper(HttpServletRequest req) {
        super(req);
        this.req = req;
    }

    public String getParameter(String parameterName) {

        if (loginField.equals(parameterName) || passwordField.equals(parameterName)) {
            return GuestCallbacksProvider.GUEST;
        } else {
            return super.getParameter(parameterName);
        }
    }

    public String getHeader(String headerName) {

        if (AUTHORIZATION.equalsIgnoreCase(headerName)) {
            return CallbackHandlerUtils.buildBasicAuthHeader(GuestCallbacksProvider.GUEST, GuestCallbacksProvider.GUEST, super.getCharacterEncoding());
        }

        return super.getHeader(headerName);
    }

}
