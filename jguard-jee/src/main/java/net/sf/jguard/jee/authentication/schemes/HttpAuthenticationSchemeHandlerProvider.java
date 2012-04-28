package net.sf.jguard.jee.authentication.schemes;

import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandlerProvider;
import net.sf.jguard.core.authentication.schemes.FilterConfigurationLocation;
import net.sf.jguard.core.technology.StatefulScopes;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.inject.Inject;
import java.net.URL;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpAuthenticationSchemeHandlerProvider extends AuthenticationSchemeHandlerProvider<HttpServletRequestAdapter, HttpServletResponseAdapter> {

    @Inject
    public HttpAuthenticationSchemeHandlerProvider(@FilterConfigurationLocation URL filterLocation,
                                                   StatefulScopes authenticationBindings) {
        super(filterLocation, authenticationBindings);
    }
}
