package net.sf.jguard.core.authentication;

import javax.security.auth.Subject;

public class AuthenticationResult {

    private AuthenticationStatus authenticationStatus;
    private Subject subject;
    private LoginContextWrapper loginContextWrapper;

    public AuthenticationResult(AuthenticationStatus authenticationStatus, LoginContextWrapper loginContextWrapper) {
        this.authenticationStatus = authenticationStatus;
        this.loginContextWrapper = loginContextWrapper;
    }

    public AuthenticationStatus getStatus() {
        return authenticationStatus;
    }

    public Subject getSubject() {
        return loginContextWrapper.getSubject();
    }
}
