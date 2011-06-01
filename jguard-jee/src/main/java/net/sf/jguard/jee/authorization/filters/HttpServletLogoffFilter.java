package net.sf.jguard.jee.authorization.filters;

import javax.inject.Inject;
import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.LogoffFilter;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HttpServletLogoffFilter extends LogoffFilter<HttpServletRequest, HttpServletResponse> {

    @Inject
    public HttpServletLogoffFilter(StatefulAuthenticationServicePoint<HttpServletRequest, HttpServletResponse> authenticationServicePoint,
                                   @Guest Subject guest,
                                   StatefulScopes scope,
                                   AuthorizationBindings<HttpServletRequest, HttpServletResponse> authorizationBindings) {
        super(authenticationServicePoint, guest, scope, authorizationBindings);
    }
}
