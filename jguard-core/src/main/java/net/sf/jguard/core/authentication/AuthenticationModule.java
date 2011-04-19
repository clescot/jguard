/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2009  Charles GAY
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

package net.sf.jguard.core.authentication;

import com.google.inject.AbstractModule;
import com.google.inject.TypeLiteral;
import net.sf.jguard.core.authentication.bindings.GuestAuthenticationBindingsProvider;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.callbackhandler.MockCallbackHandler;
import net.sf.jguard.core.authentication.callbacks.GuestCallbacksProvider;
import net.sf.jguard.core.authentication.configuration.*;
import net.sf.jguard.core.authentication.filters.AuthenticationChallengeFilter;
import net.sf.jguard.core.authentication.filters.MockAuthenticationChallengeFilter;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.authentication.schemes.FilterConfigurationLocation;
import net.sf.jguard.core.authentication.schemes.HookImplFormSchemeHandler;
import net.sf.jguard.core.authentication.schemes.MockAuthenticationSchemeHandlerProvider;
import net.sf.jguard.core.lifecycle.*;
import net.sf.jguard.core.technology.ImpersonationScopes;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.net.URL;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class AuthenticationModule extends AbstractModule {
    private AuthenticationScope authenticationScope;
    private URL authenticationConfigurationLocation;
    private URL filterConfigurationLocation;

    public AuthenticationModule(AuthenticationScope authenticationScope,
                                URL authenticationConfigurationLocation,
                                URL filterConfigurationLocation) {
        this.authenticationScope = authenticationScope;
        this.authenticationConfigurationLocation = authenticationConfigurationLocation;
        this.filterConfigurationLocation = filterConfigurationLocation;
    }

    @Override
    protected void configure() {

        bind(Configuration.class).toProvider(JGuardConfigurationProvider.class);
        bind(URL.class).annotatedWith(AuthenticationConfigurationLocation.class).toInstance(authenticationConfigurationLocation);

        bind(new TypeLiteral<Map<String, Object>>() {
        }).annotatedWith(AuthenticationConfigurationSettings.class).toProvider(AuthenticationConfigurationSettingsProvider.class);

        bind(new TypeLiteral<List<AppConfigurationEntry>>() {
        }).toProvider(AppConfigurationEntriesProvider.class);

        bind(AuthenticationScope.class).toInstance(authenticationScope);
        bind(LoginContextWrapper.class).to(LoginContextWrapperImpl.class);
        bind(URL.class).annotatedWith(FilterConfigurationLocation.class).toInstance(filterConfigurationLocation);

        //mock part
        bind(new TypeLiteral<Request<MockRequest>>() {
        }).to(MockRequestAdapter.class);
        bind(new TypeLiteral<Response<MockResponse>>() {
        }).to(MockResponseAdapter.class);
        bind(new TypeLiteral<Collection<AuthenticationSchemeHandler<MockRequest, MockResponse>>>() {
        }).toProvider(MockAuthenticationSchemeHandlerProvider.class);
        bind(JGuardCallbackHandler.class).annotatedWith(Guest.class).to(MockCallbackHandler.class);
        bind(new TypeLiteral<JGuardCallbackHandler<MockRequest, MockResponse>>() {
        }).to(MockCallbackHandler.class);
        bind(new TypeLiteral<AuthenticationChallengeFilter<MockRequest, MockResponse>>() {
        }).to(MockAuthenticationChallengeFilter.class);
        bind(new TypeLiteral<List<AuthenticationSchemeHandler<MockRequest, MockResponse>>>() {
        }).toProvider(MockAuthenticationSchemeHandlerProvider.class);
        bind(new TypeLiteral<AuthenticationServicePoint<MockRequest, MockResponse>>() {
        }).to(MockAuthenticationServicePoint.class);


        //guest part of the module
        bind(new TypeLiteral<Collection<Callback>>() {
        }).toProvider(GuestCallbacksProvider.class);
        bind(Configuration.class).annotatedWith(Guest.class).toProvider(GuestConfigurationProvider.class);
        bind(AuthenticationSchemeHandler.class).annotatedWith(Guest.class).to(HookImplFormSchemeHandler.class);
        bind(new TypeLiteral<List<AppConfigurationEntryFilter>>() {
        }).annotatedWith(Guest.class).toProvider(GuestAppConfigurationFiltersListProvider.class);
        bind(AppConfigurationEntryFilter.class).to(GuestAppConfigurationEntryFilter.class);
        bind(ImpersonationScopes.class).toProvider(GuestAuthenticationBindingsProvider.class);
        bind(Subject.class).annotatedWith(Guest.class).toProvider(GuestSubjectProvider.class);


    }
}
