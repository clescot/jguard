/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2010  Charles Lescot
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * jGuard project home page:
 * http://sourceforge.net/projects/jguard/
 */

package net.sf.jguard.core.authorization.filters;

import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.lifecycle.StatefulRequest;

import javax.security.auth.Subject;
import java.security.Permission;

/**
 * permits to trigger the 'last access denied permission' after a successful authentication,
 * if it exists. if an AccessControlException is thrown,the default permission is triggered.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class LastAccessDeniedTriggerFilter<Req extends StatefulRequest, Res extends Response> implements LastAccessDeniedFilter<Req, Res> {


    private AuthenticationServicePoint<Req, Res> authenticationServicePoint;
    protected AuthorizationBindings<Req, Res> authorizationBindings;
    private AccessControllerWrapperImpl accessControlWrapper;

    public LastAccessDeniedTriggerFilter(AuthenticationServicePoint<Req, Res> authenticationServicePoint,
                                         AuthorizationBindings<Req, Res> authorizationBindings,
                                         AccessControllerWrapperImpl accessControlWrapper) {
        this.authenticationServicePoint = authenticationServicePoint;
        this.authorizationBindings = authorizationBindings;
        this.accessControlWrapper = accessControlWrapper;
    }

    public void doFilter(Req request, Res response, FilterChain<Req, Res> chain) {

        if (!authenticationServicePoint.authenticationSucceededDuringThisRequest(request, response)) {
            //we don't handle in this case, the 'last access denied feature'
            chain.doFilter(request, response);
        } else {
            Permission lastAccessDeniedPermission = (Permission) request.getSessionAttribute(LAST_ACCESS_DENIED_PERMISSION);
            Permission postAuthenticationPermission = authorizationBindings.getPostAuthenticationPermission(request);
            Permission permissionToProceed;

            //we grab the current subject
            Subject subject = authenticationServicePoint.getCurrentSubject();
            if (null == subject) {
                throw new IllegalStateException("current subject cannot be null");
            }
            if (lastAccessDeniedPermission != null
                    && accessControlWrapper.hasPermission(subject, lastAccessDeniedPermission)) {
                permissionToProceed = lastAccessDeniedPermission;
            } else {
                permissionToProceed = postAuthenticationPermission;
            }

            //transform the permission into an underlying
            authorizationBindings.handlePermission(request, response, permissionToProceed);
            chain.doFilter(request, response);

        }
    }


}
