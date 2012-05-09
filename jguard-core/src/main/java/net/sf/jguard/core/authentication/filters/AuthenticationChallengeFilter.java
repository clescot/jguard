package net.sf.jguard.core.authentication.filters;

import com.google.inject.Provider;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.AuthenticationStatus;
import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.callbackhandler.AsynchronousJGuardCallbackHandler;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authenticate a user if the request implies the answer to an Authentication challenge.
 * if authentication succeed, the resulting Subject is used to pass through the call the
 * access control rights acquired.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class AuthenticationChallengeFilter<Req extends Request, Res extends Response> extends AuthenticationFilter<Req, Res> {

    private AuthenticationServicePoint<Req, Res> authenticationServicePoint;
    private Provider<AsynchronousJGuardCallbackHandler<Req, Res>> callbackHandlerProvider;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationChallengeFilter.class.getName());

    public AuthenticationChallengeFilter(AuthenticationServicePoint<Req, Res> authenticationServicePoint,
                                         Provider<AsynchronousJGuardCallbackHandler<Req, Res>> callbackHandlerProvider) {
        this.authenticationServicePoint = authenticationServicePoint;
        this.callbackHandlerProvider = callbackHandlerProvider;
    }

    public void doFilter(Req request, Res response, FilterChain<Req, Res> chain) {
        JGuardCallbackHandler<Req, Res> callbackHandler = callbackHandlerProvider.get();

        LoginContextWrapper loginContextWrapper = authenticationServicePoint.authenticate(callbackHandler);
        if (!AuthenticationStatus.SUCCESS.equals(loginContextWrapper.getStatus())) {
            //authentication continue with another roundtrip
            //or authentication failed (401 for HTTP)
            logger.debug("authentication does NOT succeed");
        } else {
            logger.debug("authentication succeed");
            propagateWithSecurity(loginContextWrapper.getSubject(), request, response, chain);
        }

    }


}
