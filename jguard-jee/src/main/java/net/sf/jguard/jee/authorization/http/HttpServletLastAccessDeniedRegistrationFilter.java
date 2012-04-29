package net.sf.jguard.jee.authorization.http;

import net.sf.jguard.core.authorization.filters.LastAccessDeniedRegistrationFilter;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

public class HttpServletLastAccessDeniedRegistrationFilter extends LastAccessDeniedRegistrationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter> {

}
