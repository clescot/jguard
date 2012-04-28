package net.sf.jguard.jee.authentication.filters;

import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.authentication.filters.GuestAuthenticationFilter;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.inject.Inject;
import javax.security.auth.Subject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletGuestAuthenticationFilter extends GuestAuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter> {
    @Inject
    public HttpServletGuestAuthenticationFilter(@Guest Subject guestSubject, AuthenticationServicePoint<HttpServletRequestAdapter, HttpServletResponseAdapter> httpServletRequestHttpServletResponseAuthenticationServicePoint) {
        super(guestSubject, httpServletRequestHttpServletResponseAuthenticationServicePoint);
    }
}
