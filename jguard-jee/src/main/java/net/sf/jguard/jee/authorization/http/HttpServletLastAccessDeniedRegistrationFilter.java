package net.sf.jguard.jee.authorization.http;

import javax.inject.Inject;
import net.sf.jguard.core.authorization.filters.LastAccessDeniedRegistrationFilter;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HttpServletLastAccessDeniedRegistrationFilter extends LastAccessDeniedRegistrationFilter<HttpServletRequest, HttpServletResponse> {
    @Inject
    public HttpServletLastAccessDeniedRegistrationFilter(StatefulScopes statefulScopes) {
        super(statefulScopes);
    }
}
