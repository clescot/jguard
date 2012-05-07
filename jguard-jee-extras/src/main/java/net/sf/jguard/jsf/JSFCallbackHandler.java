package net.sf.jguard.jsf;

import net.sf.jguard.core.authentication.callbackhandler.AsynchronousJGuardCallbackHandler;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;

import javax.inject.Inject;
import java.util.Collection;

public class JSFCallbackHandler extends AsynchronousJGuardCallbackHandler<FacesContextAdapter, FacesContextAdapter> {

    @Inject
    public JSFCallbackHandler(FacesContextAdapter request, FacesContextAdapter response, Collection<AuthenticationSchemeHandler<FacesContextAdapter, FacesContextAdapter>> authenticationSchemeHandlers) {
        super(request, response, authenticationSchemeHandlers);
    }

}
