package net.sf.jguard.core.authentication.filters;

import net.sf.jguard.core.authentication.AuthenticationServicePoint;
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
public abstract class GuestAuthenticationFilter<Req, Res> extends AuthenticationFilter<Req, Res> {
    private Subject guestSubject;
    private AuthenticationServicePoint<Req, Res> authenticationServicePoint;
    private static final Logger logger = LoggerFactory.getLogger(GuestAuthenticationFilter.class.getName());


    public GuestAuthenticationFilter(@Guest Subject guestSubject, AuthenticationServicePoint<Req, Res> authenticationServicePoint) {
        this.guestSubject = guestSubject;
        this.authenticationServicePoint = authenticationServicePoint;
    }


    public void doFilter(final Request<Req> request, final Response<Res> response, final FilterChain<Req, Res> chain) {
        Subject currentSubject = authenticationServicePoint.getCurrentSubject();
        if (currentSubject == null) {
            currentSubject = guestSubject;
        }
        propagateWithSecurity(currentSubject, request, response, chain);

    }

}


