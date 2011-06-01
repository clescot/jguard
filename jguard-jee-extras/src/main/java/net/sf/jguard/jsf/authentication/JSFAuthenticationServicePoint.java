package net.sf.jguard.jsf.authentication;

import javax.inject.Inject;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.faces.context.FacesContext;
import javax.security.auth.login.Configuration;
import java.util.Collection;

public class JSFAuthenticationServicePoint extends StatefulAuthenticationServicePoint<FacesContext, FacesContext> {
    @Inject
    public JSFAuthenticationServicePoint(Configuration configuration,
                                         @Guest Configuration guestConfiguration,
                                         Collection<AuthenticationSchemeHandler<FacesContext, FacesContext>> authenticationSchemeHandlers,
                                         @ApplicationName String applicationName,
                                         StatefulScopes scopes,
                                         @Guest JGuardCallbackHandler guestCallbackHandler) {
        super(configuration,
                guestConfiguration,
                authenticationSchemeHandlers,
                applicationName,
                scopes,
                guestCallbackHandler);
    }
}
