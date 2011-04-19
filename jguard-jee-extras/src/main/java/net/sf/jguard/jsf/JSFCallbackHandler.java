package net.sf.jguard.jsf;

import com.google.inject.Inject;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.faces.context.FacesContext;
import java.util.Collection;

public class JSFCallbackHandler extends JGuardCallbackHandler<FacesContext, FacesContext> {

    @Inject
    public JSFCallbackHandler(Request<FacesContext> request, Response<FacesContext> response, Collection<AuthenticationSchemeHandler<FacesContext, FacesContext>> authenticationSchemeHandlers) {
        super(request, response, authenticationSchemeHandlers);
    }

    @Override
    protected boolean isAsynchronous() {
        return true;
    }
}
