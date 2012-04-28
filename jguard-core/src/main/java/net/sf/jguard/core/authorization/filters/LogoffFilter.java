/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2011  Charles Lescot
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

import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.security.auth.Subject;

/**
 * invalidate the session, and logoff the current user, if a request implies
 * the logoff Permission.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class LogoffFilter<Req extends Request, Res extends Response> implements AuthorizationFilter<Req, Res> {

    private StatefulAuthenticationServicePoint<Req, Res> authenticationServicePoint;
    private Subject guest;
    private StatefulScopes scope;
    private AuthorizationBindings<Req, Res> authorizationBindings;

    public LogoffFilter(StatefulAuthenticationServicePoint<Req, Res> authenticationServicePoint,
                        @Guest Subject guest,
                        StatefulScopes scope,
                        AuthorizationBindings<Req, Res> authorizationBindings) {

        this.authenticationServicePoint = authenticationServicePoint;
        this.guest = guest;
        this.scope = scope;
        this.authorizationBindings = authorizationBindings;
    }

    public void doFilter(Req request, Res response, FilterChain<Req, Res> chain) {
        if (userIsLogged()
                && authenticationServicePoint.userTriesToLogout(authorizationBindings.getPermissionRequested(request))) {
            scope.invalidateSession();
            authenticationServicePoint.logout();
        }
        chain.doFilter(request, response);
    }

    private boolean userIsLogged() {
        Subject currentSubject = authenticationServicePoint.getCurrentSubject();
        return null != currentSubject
                && !guest.equals(currentSubject);
    }
}
