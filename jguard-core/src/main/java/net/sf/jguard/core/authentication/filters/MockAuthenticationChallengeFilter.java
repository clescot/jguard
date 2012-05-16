package net.sf.jguard.core.authentication.filters;

import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.callbackhandler.MockAsynchronousJGuardCallbackHandler;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockAuthenticationChallengeFilter extends AuthenticationChallengeFilter<MockRequestAdapter, MockResponseAdapter> {

    @Inject
    public MockAuthenticationChallengeFilter(AuthenticationServicePoint<MockRequestAdapter, MockResponseAdapter> authenticationServicePoint,
                                             Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> registeredAuthenticationSchemeHandlers) {
        super(authenticationServicePoint, registeredAuthenticationSchemeHandlers);
    }

    @Override
    public JGuardCallbackHandler<MockRequestAdapter, MockResponseAdapter> getCallbackHandler(MockRequestAdapter requestAdapter, MockResponseAdapter responseAdapter) {
        return new MockAsynchronousJGuardCallbackHandler(requestAdapter, responseAdapter, registeredAuthenticationSchemeHandlers);
    }
}
