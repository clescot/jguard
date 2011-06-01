package net.sf.jguard.core.authorization.filters;

import javax.inject.Inject;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.technology.StatefulScopes;

public class MockLastAccessDeniedTriggerFilter extends LastAccessDeniedTriggerFilter<MockRequest, MockResponse> {
    @Inject
    public MockLastAccessDeniedTriggerFilter(AuthenticationServicePoint<MockRequest, MockResponse> authenticationServicePoint,
                                             StatefulScopes statefulScopes,
                                             AuthorizationBindings<MockRequest, MockResponse> authorizationBindings,
                                             AccessControllerWrapperImpl accessControlWrapper) {
        super(authenticationServicePoint, statefulScopes, authorizationBindings, accessControlWrapper);
    }

    public void setAuthorizationBindings(AuthorizationBindings<MockRequest, MockResponse> authorizationBindings) {
        this.authorizationBindings = authorizationBindings;
    }

    public void setStatefulScopes(StatefulScopes statefulScopes) {
        this.statefulScopes = statefulScopes;
    }
}
