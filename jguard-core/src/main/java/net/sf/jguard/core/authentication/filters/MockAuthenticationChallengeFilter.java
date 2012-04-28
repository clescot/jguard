package net.sf.jguard.core.authentication.filters;

import com.google.inject.Provider;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockAuthenticationChallengeFilter extends AuthenticationChallengeFilter<MockRequestAdapter, MockResponseAdapter> {

    @Inject
    public MockAuthenticationChallengeFilter(AuthenticationServicePoint<MockRequestAdapter, MockResponseAdapter> authenticationServicePoint,
                                             Provider<JGuardCallbackHandler<MockRequestAdapter, MockResponseAdapter>> callbackHandlerProvider,
                                             AuthenticationManager authenticationManager) {
        super(authenticationServicePoint, callbackHandlerProvider, authenticationManager);
    }
}
