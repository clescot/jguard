package net.sf.jguard.jsf.authentication;

import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.jsf.FacesContextAdapter;

import javax.inject.Inject;
import java.util.Collection;

public class JSFAuthenticationServicePoint extends StatefulAuthenticationServicePoint<FacesContextAdapter, FacesContextAdapter> {
    @Inject
    public JSFAuthenticationServicePoint(Collection<AuthenticationSchemeHandler<FacesContextAdapter, FacesContextAdapter>> authenticationSchemeHandlers,
                                         LoginContextWrapper loginContextWrapper) {
        super(authenticationSchemeHandlers,
                loginContextWrapper
        );
    }
}
