/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2011  Charles GAY
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

import com.google.inject.Provider;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import java.util.ArrayList;
import java.util.List;

/**
 * return a <b>Restful</b> list of {@link net.sf.jguard.core.authentication.filters.AuthenticationFilter}s, i.e NOT Stateful.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public abstract class RestfulAuthenticationFiltersProvider<Req, Res> implements Provider<List<AuthenticationFilter<Req, Res>>> {


    protected List<AuthenticationFilter<Req, Res>> filters = new ArrayList<AuthenticationFilter<Req, Res>>();
    private Request<Req> request;
    private Response<Res> response;
    private AuthenticationServicePoint<Req, Res> authenticationServicePoint;
    private List<AuthenticationFilter<Req, Res>> authenticationFilters;
    private GuestPolicyEnforcementPointFilter<Req, Res> guestPolicyEnforcementPointFilter;

    public RestfulAuthenticationFiltersProvider(Request<Req> request,
                                                Response<Res> response,
                                                AuthenticationServicePoint<Req, Res> authenticationServicePoint,
                                                List<AuthenticationFilter<Req, Res>> authenticationFilters,
                                                GuestPolicyEnforcementPointFilter<Req, Res> guestPolicyEnforcementPointFilter
    ) {
        this.request = request;
        this.response = response;
        this.authenticationServicePoint = authenticationServicePoint;
        this.authenticationFilters = authenticationFilters;
        this.guestPolicyEnforcementPointFilter = guestPolicyEnforcementPointFilter;
    }

    /**
     * either the request answer to an authentication challenge,
     * so we return the regular authenticationFilters list,
     * or the request does not answer to an authentication challenge, s
     * we return the <b>guest</b>AuthenticationFilters list.
     *
     * @return
     */
    public List<AuthenticationFilter<Req, Res>> get() {
        if (authenticationServicePoint.answerToChallenge(request, response)) {
            filters.addAll(authenticationFilters);
        } else {
            filters.add(guestPolicyEnforcementPointFilter);
        }
        return filters;
    }
}
