package net.sf.jguard.core.authentication.schemes;

import com.google.inject.Provider;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockAuthenticationSchemeHandlerProvider implements Provider<List<AuthenticationSchemeHandler<MockRequest, MockResponse>>> {
    private DummyAuthenticationSchemeHandler<MockRequest, MockResponse> schemeHandler;

    @Inject
    public MockAuthenticationSchemeHandlerProvider(DummyAuthenticationSchemeHandler<MockRequest, MockResponse> schemeHandler) {

        this.schemeHandler = schemeHandler;
    }

    public List<AuthenticationSchemeHandler<MockRequest, MockResponse>> get() {
        List<AuthenticationSchemeHandler<MockRequest, MockResponse>> list = new ArrayList<AuthenticationSchemeHandler<MockRequest, MockResponse>>();
        list.add(schemeHandler);
        return list;
    }
}
