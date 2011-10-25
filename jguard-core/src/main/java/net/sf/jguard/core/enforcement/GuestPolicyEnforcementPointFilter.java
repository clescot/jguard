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

import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.authorization.filters.AuthorizationFilter;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.AccessControlException;
import java.util.List;

/**
 * wrap authenticationFilters and authorizationFilters for guest, and restful
 * authenticationFilters, to permit to try the guest way, and in case of accessControlException
 * (access denied), to use the restful authenticationFilters.
 * Guest permits to delay authentication.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public abstract class GuestPolicyEnforcementPointFilter<Req, Res> extends AuthenticationFilter<Req, Res> {
    private GuestFilterChain guestFilterChain;
    private AuthenticationFilterChain authenticationFilterChain;
      private static final Logger logger = LoggerFactory.getLogger(GuestPolicyEnforcementPointFilter.class.getName());

    public GuestPolicyEnforcementPointFilter(List<AuthenticationFilter<Req, Res>> guestAuthenticationFilters,
                                             List<AuthorizationFilter<Req, Res>> guestAuthorizationFilters,
                                             List<AuthenticationFilter<Req, Res>> restfulAuthenticationFilters,
                                             List<AuthorizationFilter<Req, Res>> restfulAuthorizationFilters) {

        guestFilterChain = new GuestFilterChain(guestAuthenticationFilters, guestAuthorizationFilters);
        authenticationFilterChain = new AuthenticationFilterChain(restfulAuthenticationFilters, restfulAuthorizationFilters);

    }

    public void doFilter(Request<Req> request, Response<Res> response, FilterChain<Req, Res> chain) {
        try {
            guestFilterChain.doFilter(request, response);
        } catch (AccessControlException ace) {
            logger.info("access is denied with user authenticated as guest. we try to authenticate it");
            authenticationFilterChain.doFilter(request, response);
        }

        chain.doFilter(request, response);
    }


    private class GuestFilterChain extends PolicyEnforcementPoint<Req, Res> {


        /**
         * @param guestAuthenticationFilters
         * @param guestAuthorizationFilters
         */
        private GuestFilterChain(List<AuthenticationFilter<Req, Res>> guestAuthenticationFilters,
                                 List<AuthorizationFilter<Req, Res>> guestAuthorizationFilters) {
            super(guestAuthenticationFilters, guestAuthorizationFilters, true);
        }


        @Override
        protected void sendThrowable(Response<Res> response, Throwable throwable) {

        }
    }


    private class AuthenticationFilterChain extends PolicyEnforcementPoint<Req, Res> {

        /**
         * @param authenticationFilters
         * @param authorizationFilters
         */
        public AuthenticationFilterChain(List<AuthenticationFilter<Req, Res>> authenticationFilters, List<AuthorizationFilter<Req, Res>> authorizationFilters) {
            super(authenticationFilters, authorizationFilters, true);
        }

        @Override
        protected void sendThrowable(Response<Res> response, Throwable throwable) {

        }
    }
}
