package net.sf.jguard.core.authentication.callbackhandler;

import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import java.util.Collection;

public class AsynchronousMockCallbackHandler extends MockCallbackHandler {
    public AsynchronousMockCallbackHandler(Request<MockRequest> request, Response<MockResponse> response, Collection<AuthenticationSchemeHandler<MockRequest, MockResponse>> authenticationSchemeHandlers) {
        super(request, response, authenticationSchemeHandlers);
    }

    protected boolean isAsynchronous() {
        return true;
    }
}
