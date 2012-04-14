package net.sf.jguard.core.authentication.callbackhandler;

import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.Response;

public class DummyMockResponse implements Response<MockResponse> {
    public MockResponse get() {
        return new MockResponse();
    }
}
