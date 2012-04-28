package net.sf.jguard.jee.authorization;

import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.PolicyDecisionPoint;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.inject.Inject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletPolicyDecisionPoint extends PolicyDecisionPoint<HttpServletRequestAdapter, HttpServletResponseAdapter> {
    /**
     * Creates a new instance of AuthorizationLifeCycle
     *
     * @param authorizationBindings
     */
    @Inject
    public HttpServletPolicyDecisionPoint(AuthorizationBindings<HttpServletRequestAdapter, HttpServletResponseAdapter> authorizationBindings,
                                          AccessControllerWrapperImpl accessControlWrapper) {
        super(authorizationBindings, accessControlWrapper);
    }
}
