package net.sf.jguard.core.authentication.schemes;

import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockGrantedAuthenticationSchemePermissionsProvider extends GrantedAuthenticationSchemePermissionsProvider<MockRequestAdapter, MockResponseAdapter> {
    @Inject
    public MockGrantedAuthenticationSchemePermissionsProvider(Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers) {
        super(authenticationSchemeHandlers);
    }
}
