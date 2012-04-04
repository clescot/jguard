package net.sf.jguard.core.authentication.schemes;

import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;

import javax.inject.Inject;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockGrantedAuthenticationSchemePermissionsProvider extends GrantedAuthenticationSchemePermissionsProvider<MockRequest, MockResponse> {
    @Inject
    public MockGrantedAuthenticationSchemePermissionsProvider(Collection<AuthenticationSchemeHandler<MockRequest, MockResponse>> authenticationSchemeHandlers) {
        super(authenticationSchemeHandlers);
    }
}
