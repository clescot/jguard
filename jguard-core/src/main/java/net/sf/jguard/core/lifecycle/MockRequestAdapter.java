package net.sf.jguard.core.lifecycle;

import javax.inject.Inject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockRequestAdapter implements Request<MockRequest> {
    private MockRequest mockRequest;

    @Inject
    public MockRequestAdapter(MockRequest mockRequest) {

        this.mockRequest = mockRequest;
    }

    public MockRequest get() {
        return mockRequest;
    }
}
