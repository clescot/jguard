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
package net.sf.jguard.jee.authentication.http;

import com.google.inject.Inject;
import com.google.inject.servlet.RequestScoped;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.principals.RolePrincipal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 * wrap the ServletRequest object to 'decorate' it to
 * respect the JAAS mechanism present in j2se.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
@RequestScoped
public class JGuardServletRequestWrapper extends HttpServletRequestWrapper {

    private Map headers = null;
    private String applicationName;
    private AuthenticationManager authenticationManager;
    private HttpServletRequest request;
    private LoginContextWrapper loginContextWrapper;

    @Inject
    public JGuardServletRequestWrapper(@ApplicationName String applicationName,
                                       AuthenticationManager authenticationManager,
                                       HttpServletRequest req, LoginContextWrapper loginContextWrapper) {
        super(req);
        this.applicationName = applicationName;
        this.authenticationManager = authenticationManager;
        this.request = req;
        this.loginContextWrapper = loginContextWrapper;
        headers = new HashMap();
    }

    /**
     * wrap the isUserInRole method to check against
     * all the {@link RolePrincipal}'s set of the Subject object.
     *
     * @param role : name of the principal(role) we are looking for
     * @return boolean :return 'true' if one of the principal the Subject
     *         owns has got the same name.return 'false' otherwise.
     */
    public boolean isUserInRole(String role) {
        return JEERequestWrapperUtil.isUserInRole(applicationName, role, loginContextWrapper);
    }


    /**
     * return a SubjectAsPrincipal object which wrap the Subject
     * in a Principal.
     *
     * @return principal
     */
    public Principal getUserPrincipal() {
        LoginContextWrapper loginContextWrapperImpl = ((LoginContextWrapper) request.getSession(true).getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER));
        return JEERequestWrapperUtil.getUserPrincipal(loginContextWrapperImpl);
    }


    /**
     * return login of the user.
     *
     * @return remote user login credential String value
     */
    public String getRemoteUser() {
        LoginContextWrapper loginContextWrapperImpl = ((LoginContextWrapper) request.getSession(true).getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER));
        if (authenticationManager == null) {
            return null;
        }
        return JEERequestWrapperUtil.getRemoteUser(loginContextWrapperImpl, authenticationManager);
    }


    public void setHeader(String headerName, String headerValue) {
        headers.put(headerName, headerValue);
    }

    public String getHeader(String headerName) {

        if (headers.containsKey(headerName)) {
            return (String) headers.get(headerName);
        } else {
            return super.getHeader(headerName);
        }
    }

}
