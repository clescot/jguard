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
package net.sf.jguard.jsf.authentication;

import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.LoginContextWrapperImpl;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.authentication.manager.JGuardAuthenticationManagerMarkups;
import net.sf.jguard.core.principals.RolePrincipal;
import net.sf.jguard.jee.authentication.http.JEERequestWrapperUtil;

import javax.inject.Inject;
import javax.portlet.PortletRequest;
import javax.portlet.PortletSession;
import java.security.Principal;

public class JGuardPortletRequestWrapper extends PortletRequestWrapper {

    @Inject
    public JGuardPortletRequestWrapper(PortletRequest request, @ApplicationName String applicationName) {
        super(request, applicationName);
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
        PortletSession session = request.getPortletSession(true);
        LoginContextWrapperImpl authUtils = ((LoginContextWrapperImpl) session.getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER, PortletSession.APPLICATION_SCOPE));
        return JEERequestWrapperUtil.isUserInRole(applicationName, role, authUtils);
    }


    /**
     * return a SubjectAsPrincipal object which wrap the Subject
     * in a Principal.
     *
     * @return principal
     */
    public Principal getUserPrincipal() {
        LoginContextWrapperImpl authUtils = ((LoginContextWrapperImpl) request.getPortletSession(true).getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER, PortletSession.APPLICATION_SCOPE));
        return JEERequestWrapperUtil.getUserPrincipal(authUtils);
    }


    /**
     * @return remote user login credential String value
     */
    public String getRemoteUser() {
        LoginContextWrapperImpl authUtils = ((LoginContextWrapperImpl) request.getPortletSession(true).getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER, PortletSession.APPLICATION_SCOPE));
        AuthenticationManager authnManager = (AuthenticationManager) request.getPortletSession(true).getAttribute(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel(), PortletSession.APPLICATION_SCOPE);

        return JEERequestWrapperUtil.getRemoteUser(authUtils, authnManager);
    }

}
