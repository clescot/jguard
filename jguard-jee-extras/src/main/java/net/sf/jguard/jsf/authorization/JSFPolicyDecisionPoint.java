package net.sf.jguard.jsf.authorization;

import javax.inject.Inject;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.PolicyDecisionPoint;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;

import javax.faces.context.FacesContext;

public class JSFPolicyDecisionPoint extends PolicyDecisionPoint<FacesContext, FacesContext> {
    /**
     * Creates a new instance of AuthorizationLifeCycle
     *
     * @param authorizationBindings
     * @param accessControlWrapper
     */
    @Inject
    public JSFPolicyDecisionPoint(AuthorizationBindings<FacesContext, FacesContext> authorizationBindings, AccessControllerWrapperImpl accessControlWrapper) {
        super(authorizationBindings, accessControlWrapper);
    }
}
