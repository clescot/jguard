package net.sf.jguard.jee;

import com.google.inject.Provider;
import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletGuestAuthenticationSchemeHandlersProvider implements Provider<Collection<AuthenticationSchemeHandler<HttpServletRequest, HttpServletResponse>>> {
    private AuthenticationSchemeHandler<HttpServletRequest, HttpServletResponse> authenticationSchemeHandler;

    @Inject
    public HttpServletGuestAuthenticationSchemeHandlersProvider(@Guest AuthenticationSchemeHandler<HttpServletRequest, HttpServletResponse> authenticationSchemeHandler) {
        this.authenticationSchemeHandler = authenticationSchemeHandler;
    }

    public Collection<AuthenticationSchemeHandler<HttpServletRequest, HttpServletResponse>> get() {
        Collection<AuthenticationSchemeHandler<HttpServletRequest, HttpServletResponse>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<HttpServletRequest, HttpServletResponse>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        return authenticationSchemeHandlers;
    }
}
