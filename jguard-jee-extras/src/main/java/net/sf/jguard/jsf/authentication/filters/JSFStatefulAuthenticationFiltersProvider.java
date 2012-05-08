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

package net.sf.jguard.jsf.authentication.filters;

import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.AsynchronousJGuardCallbackHandler;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.enforcement.GuestPolicyEnforcementPointFilter;
import net.sf.jguard.core.enforcement.StatefulAuthenticationFiltersProvider;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.jsf.FacesContextAdapter;

import javax.inject.Inject;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class JSFStatefulAuthenticationFiltersProvider extends StatefulAuthenticationFiltersProvider<FacesContextAdapter, FacesContextAdapter> {


    @Inject
    public JSFStatefulAuthenticationFiltersProvider(AsynchronousJGuardCallbackHandler<FacesContextAdapter, FacesContextAdapter> jGuardCallbackHandler,
                                                    List<AuthenticationFilter<FacesContextAdapter, FacesContextAdapter>> authenticationFilters,
                                                    GuestPolicyEnforcementPointFilter<FacesContextAdapter, FacesContextAdapter> guestPolicyEnforcementPointFilter) {
        super(jGuardCallbackHandler,
                authenticationFilters,
                guestPolicyEnforcementPointFilter,
                new AuthenticationFilter<FacesContextAdapter, FacesContextAdapter>() {
                    public void doFilter(FacesContextAdapter request, FacesContextAdapter response, FilterChain<FacesContextAdapter, FacesContextAdapter> chain) {
                        LoginContextWrapper wrapper = (LoginContextWrapper) request.get().getExternalContext().getSessionMap().get(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
                        if (null == wrapper || null == wrapper.getSubject()) {
                            throw new IllegalArgumentException("loginContext is null");
                        }
                        propagateWithSecurity(wrapper.getSubject(), request, response, chain);
                    }
                });
    }

    @Override
    protected boolean alreadyAuthenticated(FacesContextAdapter request) {
        Map session = request.get().getExternalContext().getSessionMap();
        LoginContextWrapper wrapper = (LoginContextWrapper) session.get(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
        return (null != wrapper);
    }
}
