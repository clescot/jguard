package net.sf.jguard.jee.authorization.http;

import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.authentication.schemes.GrantedAuthenticationSchemePermissionsProvider;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletGrantedPermissionsProvider extends GrantedAuthenticationSchemePermissionsProvider<HttpServletRequest, HttpServletResponse> {
    @Inject
    public HttpServletGrantedPermissionsProvider(Collection<AuthenticationSchemeHandler<HttpServletRequest, HttpServletResponse>> authenticationSchemeHandlers) {
        super(authenticationSchemeHandlers);
    }
}
