package net.sf.jguard.jee;

import com.google.inject.Provider;
import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletGuestAuthenticationSchemeHandlersProvider implements Provider<Collection<AuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>>> {
    private AuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter> authenticationSchemeHandler;

    @Inject
    public HttpServletGuestAuthenticationSchemeHandlersProvider(@Guest AuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter> authenticationSchemeHandler) {
        this.authenticationSchemeHandler = authenticationSchemeHandler;
    }

    public Collection<AuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>> get() {
        Collection<AuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        return authenticationSchemeHandlers;
    }
}
