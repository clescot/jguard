package net.sf.jguard.jsf.authorization;

import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.PolicyDecisionPoint;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.jsf.FacesContextAdapter;

import javax.inject.Inject;

public class JSFPolicyDecisionPoint extends PolicyDecisionPoint<FacesContextAdapter, FacesContextAdapter> {
    /**
     * Creates a new instance of AuthorizationLifeCycle
     *
     * @param authorizationBindings
     * @param accessControlWrapper
     */
    @Inject
    public JSFPolicyDecisionPoint(AuthorizationBindings<FacesContextAdapter, FacesContextAdapter> authorizationBindings, AccessControllerWrapperImpl accessControlWrapper) {
        super(authorizationBindings, accessControlWrapper);
    }
}
