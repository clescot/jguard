package net.sf.jguard.core.authorization.filters;

import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;

public class MockLastAccessDeniedTriggerFilter extends LastAccessDeniedTriggerFilter<MockRequestAdapter, MockResponseAdapter> {
    @Inject
    public MockLastAccessDeniedTriggerFilter(AuthenticationServicePoint<MockRequestAdapter, MockResponseAdapter> authenticationServicePoint,
                                             AuthorizationBindings<MockRequestAdapter, MockResponseAdapter> authorizationBindings,
                                             AccessControllerWrapperImpl accessControlWrapper) {
        super(authenticationServicePoint, authorizationBindings, accessControlWrapper);
    }

    public void setAuthorizationBindings(AuthorizationBindings<MockRequestAdapter, MockResponseAdapter> authorizationBindings) {
        this.authorizationBindings = authorizationBindings;
    }

}
