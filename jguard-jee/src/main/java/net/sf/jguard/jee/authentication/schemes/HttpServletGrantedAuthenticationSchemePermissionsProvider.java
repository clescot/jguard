package net.sf.jguard.jee.authentication.schemes;

import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.authentication.schemes.GrantedAuthenticationSchemePermissionsProvider;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletGrantedAuthenticationSchemePermissionsProvider extends GrantedAuthenticationSchemePermissionsProvider<HttpServletRequest, HttpServletResponse> {
    @Inject
    public HttpServletGrantedAuthenticationSchemePermissionsProvider(Collection<AuthenticationSchemeHandler<HttpServletRequest, HttpServletResponse>> authenticationSchemeHandlers) {
        super(authenticationSchemeHandlers);
    }
}
