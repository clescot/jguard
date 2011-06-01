package net.sf.jguard.core;

import javax.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;

import java.util.ArrayList;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class MockGuestAuthenticationSchemeHandlersProvider implements Provider<Collection<AuthenticationSchemeHandler<MockRequest, MockResponse>>> {
    private AuthenticationSchemeHandler<MockRequest, MockResponse> authenticationSchemeHandler;

    @Inject
    public MockGuestAuthenticationSchemeHandlersProvider(@Guest AuthenticationSchemeHandler<MockRequest, MockResponse> authenticationSchemeHandler) {
        this.authenticationSchemeHandler = authenticationSchemeHandler;
    }

    public Collection<AuthenticationSchemeHandler<MockRequest, MockResponse>> get() {
        Collection<AuthenticationSchemeHandler<MockRequest, MockResponse>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequest, MockResponse>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        return authenticationSchemeHandlers;
    }
}