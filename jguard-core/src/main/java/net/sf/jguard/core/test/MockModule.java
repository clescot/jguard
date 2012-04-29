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
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import java.security.Permissions;
import java.util.Collection;
import java.util.List;

/**
 * bindings to dummy implementations for testing purpose.
 * configure all
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockModule extends AbstractModule {
    @Override
    protected void configure() {


        //filterChain part
        bind(new TypeLiteral<FilterChain>() {
        }).to(MockPolicyEnforcementPoint.class);


        //authentication part
        bind(new TypeLiteral<AbstractAuthenticationServicePoint<MockRequestAdapter, MockResponseAdapter>>() {
        }).to(MockAuthenticationServicePoint.class);

        bind(new TypeLiteral<List<AuthenticationFilter<MockRequestAdapter, MockResponseAdapter>>>() {
        }).annotatedWith(Stateful.class).toProvider(MockStatefulAuthenticationFiltersProvider.class);

        bind(new TypeLiteral<List<AuthenticationFilter<MockRequestAdapter, MockResponseAdapter>>>() {
        }).annotatedWith(Restful.class).toProvider(MockRestfulAuthenticationFiltersProvider.class);

        bind(new TypeLiteral<List<AuthenticationFilter<MockRequestAdapter, MockResponseAdapter>>>() {
        }).toProvider(MockAuthenticationFiltersProvider.class);


        bind(new TypeLiteral<PolicyEnforcementPoint<MockRequestAdapter, MockResponseAdapter>>() {
        }).to(MockPolicyEnforcementPoint.class);


        //guest part
        bind(new TypeLiteral<GuestPolicyEnforcementPointFilter<MockRequestAdapter, MockResponseAdapter>>() {
        }).to(MockGuestPolicyEnforcementPointFilter.class);


        bind(new TypeLiteral<GuestAuthenticationFilter<MockRequestAdapter, MockResponseAdapter>>() {
        }).to(MockGuestAuthenticationFilter.class);


        bind(new TypeLiteral<List<AuthenticationFilter<MockRequestAdapter, MockResponseAdapter>>>() {
        }).annotatedWith(Guest.class).toProvider(MockGuestAuthenticationFiltersProvider.class);

        bind(new TypeLiteral<Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>>() {
        }).annotatedWith(Guest.class).toProvider(MockAuthenticationSchemeHandlerProvider.class);

        //authorization part
        bind(AuthorizationBindings.class).to(MockAuthorizationBindings.class);

        bind(Permissions.class).toProvider(MockGrantedAuthenticationSchemePermissionsProvider.class);

        bind(new TypeLiteral<LastAccessDeniedTriggerFilter<MockRequestAdapter, MockResponseAdapter>>() {
        }).to(MockLastAccessDeniedTriggerFilter.class);

        bind(new TypeLiteral<LastAccessDeniedRegistrationFilter<MockRequestAdapter, MockResponseAdapter>>() {
        }).to(MockLastAccessRegistrationFilter.class);

        bind(new TypeLiteral<AuthorizationBindings<MockRequestAdapter, MockResponseAdapter>>() {
        }).to(MockAuthorizationBindings.class);

        bind(new TypeLiteral<PolicyDecisionPoint<MockRequestAdapter, MockResponseAdapter>>() {
        }).to(MockPolicyDecisionPoint.class);

        bind(new TypeLiteral<List<AuthorizationFilter<MockRequestAdapter, MockResponseAdapter>>>() {
        }).annotatedWith(Guest.class).toProvider(MockGuestAuthorizationFiltersProvider.class);

        bind(new TypeLiteral<List<AuthorizationFilter<MockRequestAdapter, MockResponseAdapter>>>() {
        }).toProvider(MockAuthorizationFiltersProvider.class);

    }
}
