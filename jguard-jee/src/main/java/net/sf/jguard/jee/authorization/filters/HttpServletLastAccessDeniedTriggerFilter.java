package net.sf.jguard.jee.authorization.filters;

import javax.inject.Inject;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.LastAccessDeniedTriggerFilter;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HttpServletLastAccessDeniedTriggerFilter extends LastAccessDeniedTriggerFilter<HttpServletRequest, HttpServletResponse> {
    @Inject
    public HttpServletLastAccessDeniedTriggerFilter(AuthenticationServicePoint<HttpServletRequest, HttpServletResponse> authenticationServicePoint,
                                                    StatefulScopes statefulScopes,
                                                    AuthorizationBindings<HttpServletRequest, HttpServletResponse> authorizationBindings1,
                                                    AccessControllerWrapperImpl accessControlWrapper) {
        super(authenticationServicePoint, statefulScopes, authorizationBindings1, accessControlWrapper);
    }
}
