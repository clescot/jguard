package net.sf.jguard.jee.authorization.filters;

import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.LastAccessDeniedTriggerFilter;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.inject.Inject;

public class HttpServletLastAccessDeniedTriggerFilter extends LastAccessDeniedTriggerFilter<HttpServletRequestAdapter, HttpServletResponseAdapter> {
    @Inject
    public HttpServletLastAccessDeniedTriggerFilter(AuthenticationServicePoint<HttpServletRequestAdapter, HttpServletResponseAdapter> authenticationServicePoint,
                                                    AuthorizationBindings<HttpServletRequestAdapter, HttpServletResponseAdapter> authorizationBindings1,
                                                    AccessControllerWrapperImpl accessControlWrapper) {
        super(authenticationServicePoint, authorizationBindings1, accessControlWrapper);
    }
}
