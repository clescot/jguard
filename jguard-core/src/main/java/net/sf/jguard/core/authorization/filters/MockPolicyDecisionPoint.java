package net.sf.jguard.core.authorization.filters;

import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapper;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockPolicyDecisionPoint extends PolicyDecisionPoint<MockRequestAdapter, MockResponseAdapter> {
    /**
     * Creates a new instance of AuthorizationLifeCycle
     */
    @Inject
    public MockPolicyDecisionPoint(AuthorizationBindings<MockRequestAdapter, MockResponseAdapter> authorizationBindings,
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
