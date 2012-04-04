package net.sf.jguard.jee.authorization;

import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.PolicyDecisionPoint;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletPolicyDecisionPoint extends PolicyDecisionPoint<HttpServletRequest, HttpServletResponse> {
    /**
     * Creates a new instance of AuthorizationLifeCycle
     *
     * @param authorizationBindings
     */
    @Inject
    public HttpServletPolicyDecisionPoint(AuthorizationBindings<HttpServletRequest,
            HttpServletResponse> authorizationBindings,
                                          AccessControllerWrapperImpl accessControlWrapper) {
        super(authorizationBindings, accessControlWrapper);
    }
}
