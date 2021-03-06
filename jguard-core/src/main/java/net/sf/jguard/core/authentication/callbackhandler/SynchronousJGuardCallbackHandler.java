package net.sf.jguard.core.authentication.callbackhandler;

import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.Collection;

public abstract class SynchronousJGuardCallbackHandler<Req extends Request, Res extends Response> extends JGuardCallbackHandler<Req, Res> {
    public SynchronousJGuardCallbackHandler(Req request, Res response, Collection<AuthenticationSchemeHandler<Req, Res>> registeredAuthenticationSchemeHandlers) {
        super(request, response, registeredAuthenticationSchemeHandlers);
    }

    @Override
    protected void handle(Callback[] callbacks, AuthenticationSchemeHandler<Req, Res> authenticationSchemeHandler) throws UnsupportedCallbackException {
        super.handle(callbacks, authenticationSchemeHandler);
    }
}
