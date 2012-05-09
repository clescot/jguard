package net.sf.jguard.jee;

import com.google.inject.Provider;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.AsynchronousJGuardCallbackHandler;
import net.sf.jguard.core.authentication.filters.AuthenticationChallengeFilter;

import javax.inject.Inject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletAuthenticationChallengeFilter extends AuthenticationChallengeFilter<HttpServletRequestAdapter, HttpServletResponseAdapter> {
    @Inject
    public HttpServletAuthenticationChallengeFilter(AuthenticationServicePoint<HttpServletRequestAdapter, HttpServletResponseAdapter> authenticationServicePoint,
                                                    Provider<AsynchronousJGuardCallbackHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>> jGuardCallbackHandlerProvider) {
        super(authenticationServicePoint, jGuardCallbackHandlerProvider);
    }
}
