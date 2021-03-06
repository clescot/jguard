package net.sf.jguard.ext.authentication.schemes;

import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.schemes.FORMSchemeHandler;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.ext.authentication.callbacks.JCaptchaCallback;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class JCaptchaAuthenticationSchemeHandler<Req extends Request, Res extends Response> extends FORMSchemeHandler<Req, Res> {


    private Collection<Class<? extends Callback>> callbackTypes = null;

    public JCaptchaAuthenticationSchemeHandler(Map<String, String> parameters) {
        super(parameters);
        callbackTypes = new ArrayList<Class<? extends Callback>>();
        callbackTypes.add(JCaptchaCallback.class);
    }

    /**
     * unique name of the Authentication Scheme.
     *
     * @return
     */
    public String getName() {
        return "JCAPTCHA";
    }

    /**
     * return Callbacks classes needed by LoginModules to authenticate the client.
     *
     * @return
     */
    public Collection<Class<? extends Callback>> getCallbackTypes() {
        return callbackTypes;
    }


    /**
     * create a challenge in the underlying technology way.
     *
     * @param request
     * @param response
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    public abstract void buildChallenge(Req request, Res response);


    /**
     * translate in the underlying technology the authentication success.
     *
     * @param subject
     * @param request
     * @param response
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    public void authenticationSucceed(Subject subject, Req request, Res response) {
        //nothing to do
    }

    /**
     * translate in the underlying technology the authentication failure.
     *
     * @param request
     * @param response
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    public void authenticationFailed(Req request, Res response) throws AuthenticationException {
        //nothing to do
    }

    public void handleSchemeCallbacks(Req request, Res response, Callback[] cbks) throws UnsupportedCallbackException {
        String captchaAnswer = getCaptchaAnswer(request, response);
        String sessionID = getSessionID(request);
        for (Callback cb : cbks) {
            if (cb instanceof JCaptchaCallback) {
                ((JCaptchaCallback) cb).setCaptchaAnswer(captchaAnswer);
                ((JCaptchaCallback) cb).setSessionID(sessionID);
            }
        }
    }

    protected abstract String getCaptchaAnswer(Req request, Res response);

    protected abstract String getSessionID(Req request);

}
