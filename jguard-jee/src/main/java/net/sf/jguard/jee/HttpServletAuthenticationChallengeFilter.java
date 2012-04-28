package net.sf.jguard.jee;

import com.google.inject.Provider;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.filters.AuthenticationChallengeFilter;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;

import javax.inject.Inject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletAuthenticationChallengeFilter extends AuthenticationChallengeFilter<HttpServletRequestAdapter, HttpServletResponseAdapter> {
    @Inject
    public HttpServletAuthenticationChallengeFilter(AuthenticationServicePoint<HttpServletRequestAdapter, HttpServletResponseAdapter> authenticationServicePoint,
                                                    Provider<JGuardCallbackHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>> jGuardCallbackHandlerProvider,
                                                    AuthenticationManager authenticationManager) {
        super(authenticationServicePoint, jGuardCallbackHandlerProvider, authenticationManager);
    }
}
