package net.sf.jguard.jee.authorization.http;

import net.sf.jguard.core.authorization.filters.LastAccessDeniedRegistrationFilter;
import net.sf.jguard.core.technology.StatefulScopes;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.inject.Inject;

public class HttpServletLastAccessDeniedRegistrationFilter extends LastAccessDeniedRegistrationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter> {
    @Inject
    public HttpServletLastAccessDeniedRegistrationFilter(StatefulScopes statefulScopes) {
        super(statefulScopes);
    }
}
