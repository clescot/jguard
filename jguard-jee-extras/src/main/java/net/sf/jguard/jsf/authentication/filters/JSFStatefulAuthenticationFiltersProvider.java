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

package net.sf.jguard.jsf.authentication.filters;

import com.google.inject.Inject;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.enforcement.GuestPolicyEnforcementPointFilter;
import net.sf.jguard.core.enforcement.StatefulAuthenticationFiltersProvider;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.faces.context.FacesContext;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class JSFStatefulAuthenticationFiltersProvider extends StatefulAuthenticationFiltersProvider<FacesContext, FacesContext> {


    @Inject
    public JSFStatefulAuthenticationFiltersProvider(Request<FacesContext> facesContextRequest,
                                                    Response<FacesContext> facesContextResponse,
                                                    AuthenticationServicePoint<FacesContext, FacesContext> authenticationServicePoint,
                                                    List<AuthenticationFilter<FacesContext, FacesContext>> authenticationFilters,
                                                    GuestPolicyEnforcementPointFilter<FacesContext, FacesContext> guestPolicyEnforcementPointFilter) {
        super(facesContextRequest,
                facesContextResponse,
                authenticationServicePoint,
                authenticationFilters,
                guestPolicyEnforcementPointFilter,
                new AuthenticationFilter<FacesContext, FacesContext>() {
                    public void doFilter(Request<FacesContext> request, Response<FacesContext> response, FilterChain<FacesContext, FacesContext> chain) {
                        LoginContextWrapper wrapper = (LoginContextWrapper) request.get().getExternalContext().getSessionMap().get(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
                        if (null == wrapper || null == wrapper.getSubject()) {
                            throw new IllegalArgumentException("loginContext is null");
                        }
                        propagateWithSecurity(wrapper.getSubject(), request, response, chain);
                    }
                });
    }

    @Override
    protected boolean alreadyAuthenticated(Request<FacesContext> request) {
        Map session = request.get().getExternalContext().getSessionMap();
        LoginContextWrapper wrapper = (LoginContextWrapper) session.get(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
        return (null != wrapper);
    }
}
