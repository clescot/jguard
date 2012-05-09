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

package net.sf.jguard.core.enforcement;

import net.sf.jguard.core.authentication.callbackhandler.AsynchronousJGuardCallbackHandler;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import java.util.List;

/**
 * provider which supercedes the {@link net.sf.jguard.core.authentication.Restful} {@link RestfulAuthenticationFiltersProvider}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class StatefulAuthenticationFiltersProvider<Req extends Request, Res extends Response> extends RestfulAuthenticationFiltersProvider<Req, Res> {

    private Req request;
    private AuthenticationFilter<Req, Res> sessionAuthenticationFilter;

    public StatefulAuthenticationFiltersProvider(AsynchronousJGuardCallbackHandler<Req, Res> jGuardCallbackHandler,
                                                 List<AuthenticationFilter<Req, Res>> authenticationFilters,
                                                 GuestPolicyEnforcementPointFilter<Req, Res> policyEnforcementPointFilter,
                                                 AuthenticationFilter<Req, Res> sessionAuthenticationFilter,
                                                 Req request) {
        super(jGuardCallbackHandler, authenticationFilters, policyEnforcementPointFilter);
        this.sessionAuthenticationFilter = sessionAuthenticationFilter;
        this.request = request;
    }


    protected abstract boolean alreadyAuthenticated(Req request);

    /**
     * if user is already authenticated, we return an AuthenticationFilter (which grab into the HttpSession the loginContextWrapper),
     * or we return AuthenticationFilters from the RestfulAuthenticationFiltersProvider.
     *
     * @return
     */
    public final List<AuthenticationFilter<Req, Res>> get() {
        if (alreadyAuthenticated(request)) {
            filters.add(sessionAuthenticationFilter);
            return filters;
        } else {
            return super.get();
        }
    }
}
