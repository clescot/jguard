package net.sf.jguard.jee.authentication.schemes;

import javax.inject.Inject;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandlerProvider;
import net.sf.jguard.core.authentication.schemes.FilterConfigurationLocation;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URL;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class HttpAuthenticationSchemeHandlerProvider extends AuthenticationSchemeHandlerProvider<HttpServletRequest, HttpServletResponse> {

    @Inject
    public HttpAuthenticationSchemeHandlerProvider(@FilterConfigurationLocation URL filterLocation,
                                                   StatefulScopes authenticationBindings) {
        super(filterLocation, authenticationBindings);
    }
}
