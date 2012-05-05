package net.sf.jguard.core.authentication.loginmodules;

import net.sf.jguard.core.authentication.callbacks.AuthenticationChallengeForCallbackHandlerException;
import net.sf.jguard.core.authentication.callbacks.AuthenticationContinueForCallbackHandlerException;
import net.sf.jguard.core.authentication.exception.AuthenticationContinueException;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Map;

public class MockLoginModule extends UserNamePasswordLoginModule implements LoginModule {


    private boolean login = true;
    private boolean commit = true;
    private boolean abort = true;
    private boolean logout = true;
    private CallbackHandler callbackHandler;

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {

        this.callbackHandler = callbackHandler;
    }

    public boolean login() throws LoginException {
        try {
            callbackHandler.handle(new Callback[]{});
        } catch (java.io.IOException ioe) {
            throw new LoginException(ioe.toString());
        } catch (AuthenticationChallengeForCallbackHandlerException cnc) {
            throw new AuthenticationChallengeException(cnc.getMessage());
        } catch (AuthenticationContinueForCallbackHandlerException cnc) {
            throw new AuthenticationContinueException(cnc.getMessage());
        } catch (UnsupportedCallbackException uce) {
            throw new LoginException("Callback error : " + uce.getCallback().toString() +
                    " not available to authenticate the user");
        }

        return login;
    }

    public boolean commit() throws LoginException {
        return commit;
    }

    public boolean abort() throws LoginException {
        return abort;
    }

    public boolean logout() throws LoginException {
        return logout;
    }

    public boolean isLogin() {
        return login;
    }

    public void setLogin(boolean login) {
        this.login = login;
    }

    public boolean isCommit() {
        return commit;
    }

    public void setCommit(boolean commit) {
        this.commit = commit;
    }

    public boolean isAbort() {
        return abort;
    }

    public void setAbort(boolean abort) {
        this.abort = abort;
    }

    public boolean isLogout() {
        return logout;
    }

    public void setLogout(boolean logout) {
        this.logout = logout;
    }
}
