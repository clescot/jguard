package net.sf.jguard.core.authentication.callbacks;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class AuthenticationContinueForCallbackHandlerException extends UnsupportedCallbackException {
    public AuthenticationContinueForCallbackHandlerException(Callback callback) {
        super(callback);
    }

    public AuthenticationContinueForCallbackHandlerException(Callback callback, String msg) {
        super(callback, msg);
    }
}
