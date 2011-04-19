package net.sf.jguard.jee;

import com.google.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.filters.AuthenticationChallengeFilter;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class HttpServletAuthenticationChallengeFilter extends AuthenticationChallengeFilter<HttpServletRequest, HttpServletResponse> {
    @Inject
    public HttpServletAuthenticationChallengeFilter(AuthenticationServicePoint<HttpServletRequest, HttpServletResponse> authenticationServicePoint,
                                                    Provider<JGuardCallbackHandler<HttpServletRequest, HttpServletResponse>> jGuardCallbackHandlerProvider,
                                                    AuthenticationManager authenticationManager) {
        super(authenticationServicePoint, jGuardCallbackHandlerProvider, authenticationManager);
    }
}
