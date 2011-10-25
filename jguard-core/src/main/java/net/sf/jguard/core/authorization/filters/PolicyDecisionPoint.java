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


package net.sf.jguard.core.authorization.filters;

import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapper;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import javax.security.auth.Subject;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.Permission;

/**
 * decide if access,expressed as a Permission, is granted or not.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public abstract class PolicyDecisionPoint<Req, Res> implements AuthorizationFilter<Req, Res> {

    private static final Logger logger = LoggerFactory.getLogger(PolicyDecisionPoint.class.getName());
    protected AuthorizationBindings<Req, Res> authorizationBindings = null;
    protected AccessControllerWrapper accessControllerWrapper;
    public static final String PERMISSION = "permission";

    /**
     * @param authorizationBindings
     * @param accessControllerWrapper
     */
    public PolicyDecisionPoint(AuthorizationBindings<Req, Res> authorizationBindings,
                               AccessControllerWrapper accessControllerWrapper) {
        this.authorizationBindings = authorizationBindings;
        this.accessControllerWrapper = accessControllerWrapper;
    }

    /**
     * add a security check.
     * return silently if access is granted, otherwise, throws an AccessControlException.
     *
     * @param request
     * @param response
     * @param chain
     * @throws AccessControlException when access is not granted
     */
    public void doFilter(Request<Req> request, Response<Res> response, FilterChain<Req, Res> chain) {
        Permission permissionRequested = authorizationBindings.getPermissionRequested(request);
        if (null == permissionRequested) {
            throw new IllegalStateException("no permission is requested ... i.e, authorizationBindings cannot represent as a Permission the actual request");
        }
        try {
            MDC.put(PERMISSION, permissionRequested.getClass().getSimpleName() + "|" + permissionRequested.getName() + "|" + permissionRequested.getActions());

            Subject subject = Subject.getSubject(AccessController.getContext());

            if (!accessControllerWrapper.hasPermission(subject, permissionRequested)) {

                logger.debug(" access is denied ");
                //403 for HTTP
                throw new AccessControlException("access denied to Permission ", permissionRequested);
            } else {
                //access granted
                logger.debug(" authorize access to resource protected by permission " + permissionRequested.getClass().getName() + " name=" + permissionRequested.getName() + " actions=" + permissionRequested.getActions());
                chain.doFilter(request, response);
            }
        } finally {
            MDC.remove(PERMISSION);
        }
    }

}
