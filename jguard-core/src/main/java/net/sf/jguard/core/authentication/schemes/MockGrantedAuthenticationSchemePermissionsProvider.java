package net.sf.jguard.core.authentication.schemes;

import javax.inject.Inject;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;

import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class MockGrantedAuthenticationSchemePermissionsProvider extends GrantedAuthenticationSchemePermissionsProvider<MockRequest, MockResponse> {
    @Inject
    public MockGrantedAuthenticationSchemePermissionsProvider(Collection<AuthenticationSchemeHandler<MockRequest, MockResponse>> authenticationSchemeHandlers) {
        super(authenticationSchemeHandlers);
    }
}
