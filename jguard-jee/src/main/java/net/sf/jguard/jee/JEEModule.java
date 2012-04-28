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

package net.sf.jguard.jee;

import com.google.inject.AbstractModule;
import com.google.inject.TypeLiteral;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.authentication.Stateful;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.filters.AuthenticationChallengeFilter;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.authentication.filters.GuestAuthenticationFilter;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.*;
import net.sf.jguard.core.authorization.permissions.PermissionFactory;
import net.sf.jguard.core.enforcement.GuestPolicyEnforcementPointFilter;
import net.sf.jguard.core.enforcement.PolicyEnforcementPoint;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.technology.Scopes;
import net.sf.jguard.core.technology.StatefulScopes;
import net.sf.jguard.jee.authentication.callbacks.HttpServletCallbackHandler;
import net.sf.jguard.jee.authentication.filters.*;
import net.sf.jguard.jee.authentication.http.HttpServletAuthenticationServicePoint;
import net.sf.jguard.jee.authentication.http.HttpServletScopes;
import net.sf.jguard.jee.authentication.http.JGuardServletRequestWrapper;
import net.sf.jguard.jee.authentication.schemes.HttpAuthenticationSchemeHandlerProvider;
import net.sf.jguard.jee.authentication.schemes.HttpServletGrantedAuthenticationSchemePermissionsProvider;
import net.sf.jguard.jee.authorization.HttpServletAuthorizationBindings;
import net.sf.jguard.jee.authorization.HttpServletPolicyDecisionPoint;
import net.sf.jguard.jee.authorization.filters.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.security.Permissions;
import java.util.Collection;
import java.util.List;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class JEEModule extends AbstractModule {

    @Override
    protected void configure() {

        //bindings for the generic filterChain
        bind(new TypeLiteral<Request<HttpServletRequest>>() {
        }).to(HttpServletRequestAdapter.class);
        bind(new TypeLiteral<Response<HttpServletResponse>>() {
        }).to(HttpServletResponseAdapter.class);

        bind(Request.class).to(HttpServletRequestAdapter.class);
        bind(Response.class).to(HttpServletResponseAdapter.class);


        bind(new TypeLiteral<FilterChain>() {
        }).to(HttpServletPolicyEnforcementPoint.class);
        bind(new TypeLiteral<PolicyEnforcementPoint<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletPolicyEnforcementPoint.class);

        bind(Scopes.class).to(HttpServletScopes.class);

        bind(HttpServletRequestWrapper.class).to(JGuardServletRequestWrapper.class);


        //bindings for the authentication part


        //stateful part
        bind(new TypeLiteral<List<AuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>>() {
        }).annotatedWith(Stateful.class).toProvider(HttpServletStatefulAuthenticationFiltersProvider.class);


        //restful part
        bind(new TypeLiteral<List<AuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>>() {
        }).toProvider(HttpServletAuthenticationFiltersProvider.class);


        //guest part
        bind(new TypeLiteral<GuestPolicyEnforcementPointFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletGuestPolicyEnforcementPointFilter.class);

        bind(new TypeLiteral<List<AuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>>() {
        }).annotatedWith(Guest.class).toProvider(HttpServletGuestAuthenticationFiltersProvider.class);

        bind(new TypeLiteral<GuestAuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletGuestAuthenticationFilter.class);

        //authentication background
        bind(new TypeLiteral<Collection<AuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>>>() {
        }).toProvider(HttpAuthenticationSchemeHandlerProvider.class);

        Class<? extends StatefulScopes> authenticationBindingsClass = HttpServletScopes.class;
        bind(StatefulScopes.class).to(authenticationBindingsClass);

        bind(new TypeLiteral<StatefulAuthenticationServicePoint<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletAuthenticationServicePoint.class);
        bind(new TypeLiteral<AuthenticationServicePoint<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletAuthenticationServicePoint.class);
        bind(JGuardCallbackHandler.class).to(HttpServletCallbackHandler.class);


        bind(new TypeLiteral<JGuardCallbackHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletCallbackHandler.class);

        bind(new TypeLiteral<AuthenticationChallengeFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletAuthenticationChallengeFilter.class);


        //bindings for the authorization part

        //stateful part
        bind(new TypeLiteral<LogoffFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletLogoffFilter.class);


        //restful part
        bind(new TypeLiteral<List<AuthorizationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>>() {
        }).toProvider(HttpServletAuthorizationFiltersProvider.class);

        bind(new TypeLiteral<LastAccessDeniedTriggerFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletLastAccessDeniedTriggerFilter.class);


        //guest part
        bind(new TypeLiteral<List<AuthorizationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>>() {
        }).annotatedWith(Guest.class).toProvider(HttpServletGuestAuthorizationFiltersProvider.class);

        bind(new TypeLiteral<LastAccessDeniedRegistrationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletLastAccessDeniedRegistrationFilter.class);


        //underlying

        bind(new TypeLiteral<AuthorizationBindings<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletAuthorizationBindings.class);

        bind(new TypeLiteral<PolicyDecisionPoint<HttpServletRequestAdapter, HttpServletResponseAdapter>>() {
        }).to(HttpServletPolicyDecisionPoint.class);

        bind(Permissions.class).toProvider(HttpServletGrantedAuthenticationSchemePermissionsProvider.class);


        bind(new TypeLiteral<PermissionFactory<HttpServletRequestAdapter>>() {
        }).to(HttpPermissionFactory.class);

    }


}
