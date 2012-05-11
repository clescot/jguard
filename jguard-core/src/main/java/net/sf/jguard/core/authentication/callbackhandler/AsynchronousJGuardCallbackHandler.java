package net.sf.jguard.core.authentication.callbackhandler;

import net.sf.jguard.core.authentication.callbacks.AuthenticationChallengeForCallbackHandlerException;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.Collection;

public abstract class AsynchronousJGuardCallbackHandler<Req extends Request, Res extends Response> extends JGuardCallbackHandler<Req, Res> {
    public AsynchronousJGuardCallbackHandler(Req request, Res response, Collection<AuthenticationSchemeHandler<Req, Res>> registeredAuthenticationSchemeHandlers) {
        super(request, response, registeredAuthenticationSchemeHandlers);
    }

    @Override
    protected void handle(Callback[] callbacks, AuthenticationSchemeHandler<Req, Res> authenticationSchemeHandler) throws UnsupportedCallbackException {
        if (!authenticationSchemeHandler.answerToChallenge(request, response)
                && authenticationSchemeHandler.impliesChallenge()) {
            //user has not yet tried to answer to an authentication challenge
            //and we need some authentication informations
            //we build a new challenge in response
            authenticationSchemeHandler.buildChallenge(request, response);

            throw new AuthenticationChallengeForCallbackHandlerException(null, authenticationSchemeHandler.getName());
        }
        super.handle(callbacks, authenticationSchemeHandler);


    }

    /**
     * return <b>true</b> if the user <b>tries</b> to answer to an authentication challenge
     * validated by an AuthenticationSchemeHandler.
     *
     * @return
     */
    public boolean answerToChallenge() {
        for (AuthenticationSchemeHandler<Req, Res> handler : registeredAuthenticationSchemeHandlers) {
            boolean answerToChallenge = handler.answerToChallenge(request, response);
            if (answerToChallenge) {
                return true;
            }
        }

        return false;
    }
}
