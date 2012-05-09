package net.sf.jguard.core.authentication.callbackhandler;

import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;
import java.util.Collection;

public class MockAsynchronousJGuardCallbackHandler extends AsynchronousJGuardCallbackHandler<MockRequestAdapter, MockResponseAdapter> {

    @Inject
    public MockAsynchronousJGuardCallbackHandler(MockRequestAdapter request, MockResponseAdapter response, Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> registeredAuthenticationSchemeHandlers) {
        super(request, response, registeredAuthenticationSchemeHandlers);
    }
}
