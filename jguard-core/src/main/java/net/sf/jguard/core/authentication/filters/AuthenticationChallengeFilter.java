package net.sf.jguard.core.authentication.filters;

import net.sf.jguard.core.authentication.AuthenticationResult;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.AuthenticationStatus;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * Authenticate a user if the request implies the answer to an Authentication challenge.
 * if authentication succeed, the resulting Subject is used to pass through the call the
 * access control rights acquired.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class AuthenticationChallengeFilter<Req extends Request, Res extends Response> extends AuthenticationFilter<Req, Res> {

    private AuthenticationServicePoint<Req, Res> authenticationServicePoint;
    protected Collection<AuthenticationSchemeHandler<Req, Res>> registeredAuthenticationSchemeHandlers;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationChallengeFilter.class.getName());

    public AuthenticationChallengeFilter(AuthenticationServicePoint<Req, Res> authenticationServicePoint,
                                         Collection<AuthenticationSchemeHandler<Req, Res>> registeredAuthenticationSchemeHandlers) {
        this.authenticationServicePoint = authenticationServicePoint;
        this.registeredAuthenticationSchemeHandlers = registeredAuthenticationSchemeHandlers;
    }

    public void doFilter(Req request, Res response, FilterChain<Req, Res> chain) {
        JGuardCallbackHandler<Req, Res> callbackHandler = getCallbackHandler(request, response);

        AuthenticationResult authenticationResult = authenticationServicePoint.authenticate(callbackHandler);
        if (!AuthenticationStatus.SUCCESS.equals(authenticationResult.getStatus())) {
            //authentication continue with another roundtrip
            //or authentication failed (401 for HTTP)
            logger.debug("authentication does NOT succeed");
        } else {
            logger.debug("authentication succeed");
            propagateWithSecurity(authenticationResult.getSubject(), request, response, chain);
        }

    }

    protected abstract JGuardCallbackHandler<Req, Res> getCallbackHandler(Req req, Res res);
}
