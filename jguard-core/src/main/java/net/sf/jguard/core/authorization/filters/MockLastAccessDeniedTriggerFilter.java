package net.sf.jguard.core.authorization.filters;

import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.inject.Inject;

public class MockLastAccessDeniedTriggerFilter extends LastAccessDeniedTriggerFilter<MockRequestAdapter, MockResponseAdapter> {
    @Inject
    public MockLastAccessDeniedTriggerFilter(AuthenticationServicePoint<MockRequestAdapter, MockResponseAdapter> authenticationServicePoint,
                                             StatefulScopes statefulScopes,
                                             AuthorizationBindings<MockRequestAdapter, MockResponseAdapter> authorizationBindings,
                                             AccessControllerWrapperImpl accessControlWrapper) {
        super(authenticationServicePoint, statefulScopes, authorizationBindings, accessControlWrapper);
    }

    public void setAuthorizationBindings(AuthorizationBindings<MockRequestAdapter, MockResponseAdapter> authorizationBindings) {
        this.authorizationBindings = authorizationBindings;
    }

    public void setStatefulScopes(StatefulScopes statefulScopes) {
        this.statefulScopes = statefulScopes;
    }
}
