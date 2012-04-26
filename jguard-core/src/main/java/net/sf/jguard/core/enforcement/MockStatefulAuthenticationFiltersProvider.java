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

import net.sf.jguard.core.authentication.Restful;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.inject.Inject;
import java.util.List;


public class MockStatefulAuthenticationFiltersProvider extends StatefulAuthenticationFiltersProvider<MockRequest, MockResponse> {


    @Inject
    public MockStatefulAuthenticationFiltersProvider(JGuardCallbackHandler<MockRequest, MockResponse> jGuardCallbackHandler,
                                                     @Restful List<AuthenticationFilter<MockRequest, MockResponse>> authenticationFilters,
                                                     GuestPolicyEnforcementPointFilter<MockRequest, MockResponse> guestPolicyEnforcementPointFilter) {
        super(jGuardCallbackHandler, authenticationFilters, guestPolicyEnforcementPointFilter, new AuthenticationFilter<MockRequest, MockResponse>() {

            public void doFilter(Request<MockRequest> request, Response<MockResponse> response, FilterChain<MockRequest, MockResponse> chain) {

            }
        });
    }


    @Override
    protected boolean alreadyAuthenticated(Request<MockRequest> mockRequestRequest) {
        return false;
    }
}
