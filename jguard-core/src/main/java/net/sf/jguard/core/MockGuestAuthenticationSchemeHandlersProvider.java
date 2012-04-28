package net.sf.jguard.core;

import com.google.inject.Provider;
import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockGuestAuthenticationSchemeHandlersProvider implements Provider<Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>> {
    private AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter> authenticationSchemeHandler;

    @Inject
    public MockGuestAuthenticationSchemeHandlersProvider(@Guest AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter> authenticationSchemeHandler) {
        this.authenticationSchemeHandler = authenticationSchemeHandler;
    }

    public Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> get() {
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        return authenticationSchemeHandlers;
    }
}