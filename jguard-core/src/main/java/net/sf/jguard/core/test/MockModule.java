package net.sf.jguard.core.test;

import com.google.inject.AbstractModule;
import com.google.inject.TypeLiteral;
import net.sf.jguard.core.authentication.*;
import net.sf.jguard.core.authentication.filters.*;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.authentication.schemes.MockAuthenticationSchemeHandlerProvider;
import net.sf.jguard.core.authentication.schemes.MockGrantedAuthenticationSchemePermissionsProvider;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.MockAuthorizationBindings;
import net.sf.jguard.core.authorization.filters.*;
import net.sf.jguard.core.enforcement.*;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.technology.MockScopes;
import net.sf.jguard.core.technology.Scopes;
import net.sf.jguard.core.technology.StatefulScopes;

import java.security.Permissions;
import java.util.Collection;
import java.util.List;

/**
 * bindings to dummy implementations for testing purpose.
 * configure all
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class MockModule extends AbstractModule {
    @Override
    protected void configure() {


        //filterChain part
        bind(new TypeLiteral<FilterChain>() {
        }).to(MockPolicyEnforcementPoint.class);
        Class<? extends StatefulScopes> mockScopesClass = MockScopes.class;
        bind(StatefulScopes.class).to(mockScopesClass);
        bind(Scopes.class).to(mockScopesClass);

        //authentication part
        bind(new TypeLiteral<AbstractAuthenticationServicePoint<MockRequest, MockResponse>>() {
        }).to(MockAuthenticationServicePoint.class);

        bind(new TypeLiteral<List<AuthenticationFilter<MockRequest, MockResponse>>>() {
        }).annotatedWith(Stateful.class).toProvider(MockStatefulAuthenticationFiltersProvider.class);

        bind(new TypeLiteral<List<AuthenticationFilter<MockRequest, MockResponse>>>() {
        }).annotatedWith(Restful.class).toProvider(MockRestfulAuthenticationFiltersProvider.class);

        bind(new TypeLiteral<List<AuthenticationFilter<MockRequest, MockResponse>>>() {
        }).toProvider(MockAuthenticationFiltersProvider.class);


        bind(new TypeLiteral<PolicyEnforcementPoint<MockRequest, MockResponse>>() {
        }).to(MockPolicyEnforcementPoint.class);


        //guest part
        bind(new TypeLiteral<GuestPolicyEnforcementPointFilter<MockRequest, MockResponse>>() {
        }).to(MockGuestPolicyEnforcementPointFilter.class);


        bind(new TypeLiteral<GuestAuthenticationFilter<MockRequest, MockResponse>>() {
        }).to(MockGuestAuthenticationFilter.class);


        bind(new TypeLiteral<List<AuthenticationFilter<MockRequest, MockResponse>>>() {
        }).annotatedWith(Guest.class).toProvider(MockGuestAuthenticationFiltersProvider.class);

        bind(new TypeLiteral<Collection<AuthenticationSchemeHandler<MockRequest, MockResponse>>>() {
        }).annotatedWith(Guest.class).toProvider(MockAuthenticationSchemeHandlerProvider.class);

        //authorization part
        bind(AuthorizationBindings.class).to(MockAuthorizationBindings.class);

        bind(Permissions.class).toProvider(MockGrantedAuthenticationSchemePermissionsProvider.class);

        bind(new TypeLiteral<LastAccessDeniedTriggerFilter<MockRequest, MockResponse>>() {
        }).to(MockLastAccessDeniedTriggerFilter.class);

        bind(new TypeLiteral<LastAccessDeniedRegistrationFilter<MockRequest, MockResponse>>() {
        }).to(MockLastAccessRegistrationFilter.class);

        bind(new TypeLiteral<AuthorizationBindings<MockRequest, MockResponse>>() {
        }).to(MockAuthorizationBindings.class);

        bind(new TypeLiteral<PolicyDecisionPoint<MockRequest, MockResponse>>() {
        }).to(MockPolicyDecisionPoint.class);

        bind(new TypeLiteral<List<AuthorizationFilter<MockRequest, MockResponse>>>() {
        }).annotatedWith(Guest.class).toProvider(MockGuestAuthorizationFiltersProvider.class);

        bind(new TypeLiteral<List<AuthorizationFilter<MockRequest, MockResponse>>>() {
        }).toProvider(MockAuthorizationFiltersProvider.class);

    }
}
