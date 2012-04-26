package net.sf.jguard.jee.authentication.http;

import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.inject.Inject;
import javax.security.auth.login.Configuration;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletAuthenticationServicePoint extends StatefulAuthenticationServicePoint<HttpServletRequest, HttpServletResponse> {
    @Inject
    public HttpServletAuthenticationServicePoint(Configuration configuration,
                                                 Collection<AuthenticationSchemeHandler<HttpServletRequest, HttpServletResponse>> authenticationSchemeHandlers,
                                                 @ApplicationName String applicationName,
                                                 StatefulScopes scopes) {
        super(configuration,
                authenticationSchemeHandlers,
                applicationName,
                scopes);
    }
}
