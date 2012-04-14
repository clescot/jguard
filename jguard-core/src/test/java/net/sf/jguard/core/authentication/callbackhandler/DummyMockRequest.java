package net.sf.jguard.core.authentication.callbackhandler;

import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.Request;

public class DummyMockRequest implements Request<MockRequest> {
    public MockRequest get() {
        return new MockRequest();
    }
}
