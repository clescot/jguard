package net.sf.jguard.jee;

import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.filters.AuthenticationChallengeFilter;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.jee.authentication.callbacks.HttpServletCallbackHandler;

import javax.inject.Inject;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletAuthenticationChallengeFilter extends AuthenticationChallengeFilter<HttpServletRequestAdapter, HttpServletResponseAdapter> {
    @Inject
    public HttpServletAuthenticationChallengeFilter(AuthenticationServicePoint<HttpServletRequestAdapter, HttpServletResponseAdapter> authenticationServicePoint,
                                                    Collection<AuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>> registeredAuthenticationSchemeHandlers) {
        super(authenticationServicePoint, registeredAuthenticationSchemeHandlers);
    }


    @Override
    public JGuardCallbackHandler<HttpServletRequestAdapter, HttpServletResponseAdapter> getCallbackHandler(HttpServletRequestAdapter requestAdapter, HttpServletResponseAdapter responseAdapter) {
        return new HttpServletCallbackHandler(requestAdapter, responseAdapter, registeredAuthenticationSchemeHandlers);
    }
}
