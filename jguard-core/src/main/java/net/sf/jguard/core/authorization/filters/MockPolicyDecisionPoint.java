package net.sf.jguard.core.authorization.filters;

import com.google.inject.Inject;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapper;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class MockPolicyDecisionPoint extends PolicyDecisionPoint<MockRequest, MockResponse> {
    /**
     * Creates a new instance of AuthorizationLifeCycle
     */
    @Inject
    public MockPolicyDecisionPoint(AuthorizationBindings<MockRequest, MockResponse> authorizationBindings,
                                   AccessControllerWrapper accessControllerWrapper) {
        super(authorizationBindings, accessControllerWrapper);
    }

    public void setAuthorizationBindings(AuthorizationBindings authorizationBindings) {
        this.authorizationBindings = authorizationBindings;
    }

    public void setAccessControlWrapper(AccessControllerWrapper accessControlWrapper) {
        this.accessControllerWrapper = accessControlWrapper;
    }
}
