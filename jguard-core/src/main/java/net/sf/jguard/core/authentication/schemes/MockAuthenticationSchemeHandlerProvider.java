package net.sf.jguard.core.authentication.schemes;

import com.google.inject.Provider;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockAuthenticationSchemeHandlerProvider implements Provider<List<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>> {
    private DummyAuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter> schemeHandler;

    @Inject
    public MockAuthenticationSchemeHandlerProvider(DummyAuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter> schemeHandler) {

        this.schemeHandler = schemeHandler;
    }

    public List<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> get() {
        List<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> list = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        list.add(schemeHandler);
        return list;
    }
}
