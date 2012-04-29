package net.sf.jguard.jee.authorization.http;

import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.authentication.schemes.GrantedAuthenticationSchemePermissionsProvider;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.inject.Inject;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletGrantedPermissionsProvider extends GrantedAuthenticationSchemePermissionsProvider<HttpServletRequestAdapter, HttpServletResponseAdapter> {
    @Inject
    public HttpServletGrantedPermissionsProvider(Collection<AuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>> authenticationSchemeHandlers) {
        super(authenticationSchemeHandlers);
    }
}
