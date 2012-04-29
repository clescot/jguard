package net.sf.jguard.jee.authorization.filters;

import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.LogoffFilter;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.inject.Inject;
import javax.security.auth.Subject;

public class HttpServletLogoffFilter extends LogoffFilter<HttpServletRequestAdapter, HttpServletResponseAdapter> {

    @Inject
    public HttpServletLogoffFilter(StatefulAuthenticationServicePoint<HttpServletRequestAdapter, HttpServletResponseAdapter> authenticationServicePoint,
                                   @Guest Subject guest,
                                   AuthorizationBindings<HttpServletRequestAdapter, HttpServletResponseAdapter> authorizationBindings) {
        super(authenticationServicePoint, guest, authorizationBindings);
    }
}
