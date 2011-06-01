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

package net.sf.jguard.jee.authorization;

import javax.inject.Inject;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.LastAccessDeniedFilter;
import net.sf.jguard.core.authorization.permissions.PermissionFactory;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.technology.StatefulScopes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Permission;

/**
 * Servlet-based implementation of {@link net.sf.jguard.core.authorization.AuthorizationBindings}.
 * useful for web frameworks which rely on the Servlet API like Struts 1.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class HttpServletAuthorizationBindings implements AuthorizationBindings<HttpServletRequest, HttpServletResponse> {

    private static final Logger logger = LoggerFactory.getLogger(HttpServletAuthorizationBindings.class.getName());

    private PermissionFactory<HttpServletRequest> permissionFactory;
    private StatefulScopes scopes;
    public final static String POST_AUTHENTICATION_PERMISSION = "postAuthenticationPermission";

    /**
     * Creates a new instance of HttpServletAuthorizationBindings.
     *
     * @param permissionFactory
     */
    @Inject
    public HttpServletAuthorizationBindings(PermissionFactory<HttpServletRequest> permissionFactory,
                                            StatefulScopes scopes) {
        this.permissionFactory = permissionFactory;
        this.scopes = scopes;
    }


    public Permission getPermissionRequested(Request<HttpServletRequest> request) {
        return permissionFactory.getPermission(request);
    }

    public void setLastAccessDeniedPermission(Request<HttpServletRequest> request, Permission permission) {
        scopes.setSessionAttribute(LastAccessDeniedFilter.LAST_ACCESS_DENIED_PERMISSION, permission);
    }


    public Permission getPostAuthenticationPermission(Request<HttpServletRequest> httpServletRequestRequest) {
        return (Permission) scopes.getSessionAttribute(POST_AUTHENTICATION_PERMISSION);
    }

    public void accessDenied(Request<HttpServletRequest> request, Response<HttpServletResponse> response) {
        HttpServletRequest httpServletRequest = request.get();
        HttpServletResponse httpServletResponse = response.get();

        if (logger.isDebugEnabled()) {
            logger.debug(" access denied to " + httpServletRequest.getRequestURI());
        }

        logger.debug(" access is denied to " + httpServletRequest.getRequestURI() + " jGuard send 403 http code ");
        httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
        try {
            if (!httpServletResponse.isCommitted()) {
                httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "access is denied to " + httpServletRequest.getRequestURI());
            }
        } catch (IOException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }

    }

    public void handlePermission(Request<HttpServletRequest> request,
                                 Response<HttpServletResponse> response,
                                 Permission permission) {
        if (permission.getClass().isAssignableFrom(URLPermission.class)) {
            URLPermission urlPermission = (URLPermission) permission;
            String uri = urlPermission.getURI();
            try {
                response.get().sendRedirect(response.get().encodeRedirectURL(request.get().getContextPath() + uri));
            } catch (IOException ex) {
                logger.error(ex.getMessage(), ex);
                throw new AuthenticationException(ex);
            }
        }
    }


}
