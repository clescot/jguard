package net.sf.jguard.core.authentication.filters;

import com.google.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class MockAuthenticationChallengeFilter extends AuthenticationChallengeFilter<MockRequest, MockResponse> {

    @Inject
    public MockAuthenticationChallengeFilter(AuthenticationServicePoint<MockRequest, MockResponse> authenticationServicePoint,
                                             Provider<JGuardCallbackHandler<MockRequest, MockResponse>> callbackHandlerProvider,
                                             AuthenticationManager authenticationManager) {
        super(authenticationServicePoint, callbackHandlerProvider, authenticationManager);
    }
}
