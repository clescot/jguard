package net.sf.jguard.core.authentication.callbackhandler;

import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import java.util.Collection;

public class SynchronousJGuardCallbackHandler<Req extends Request, Res extends Response> extends JGuardCallbackHandler<Req, Res> {
    public SynchronousJGuardCallbackHandler(Req request, Res response, Collection<AuthenticationSchemeHandler<Req, Res>> registeredAuthenticationSchemeHandlers) {
        super(request, response, registeredAuthenticationSchemeHandlers);
    }

    @Override
    protected boolean isAsynchronous() {
        return false;
    }
}
