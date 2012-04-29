package net.sf.jguard.jee.authentication.http;

import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.inject.Inject;
import javax.security.auth.login.Configuration;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletAuthenticationServicePoint extends StatefulAuthenticationServicePoint<HttpServletRequestAdapter, HttpServletResponseAdapter> {
    @Inject
    public HttpServletAuthenticationServicePoint(Configuration configuration,
                                                 Collection<AuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter>> authenticationSchemeHandlers,
                                                 @ApplicationName String applicationName) {
        super(configuration,
                authenticationSchemeHandlers,
                applicationName);
    }
}
