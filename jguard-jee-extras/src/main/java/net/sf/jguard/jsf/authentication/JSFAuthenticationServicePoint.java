package net.sf.jguard.jsf.authentication;

import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.security.auth.login.Configuration;
import java.util.Collection;

public class JSFAuthenticationServicePoint extends StatefulAuthenticationServicePoint<FacesContext, FacesContext> {
    @Inject
    public JSFAuthenticationServicePoint(Configuration configuration,
                                         Collection<AuthenticationSchemeHandler<FacesContext, FacesContext>> authenticationSchemeHandlers,
                                         @ApplicationName String applicationName,
                                         StatefulScopes scopes) {
        super(configuration,
                authenticationSchemeHandlers,
                applicationName,
                scopes);
    }
}
