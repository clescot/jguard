package net.sf.jguard.core.authentication.filters;

import net.sf.jguard.core.authentication.AbstractAuthenticationServicePoint;
import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class GuestAuthenticationFilter<Req extends Request, Res extends Response> extends AuthenticationFilter<Req, Res> {
    private Subject guestSubject;
    private static final Logger logger = LoggerFactory.getLogger(GuestAuthenticationFilter.class.getName());


    public GuestAuthenticationFilter(@Guest Subject guestSubject) {
        this.guestSubject = guestSubject;
    }


    public void doFilter(final Req request, final Res response, final FilterChain<Req, Res> chain) {
        Subject currentSubject = AbstractAuthenticationServicePoint.getCurrentSubject();
        if (currentSubject == null) {
            currentSubject = guestSubject;
        }
        propagateWithSecurity(currentSubject, request, response, chain);

    }

}


