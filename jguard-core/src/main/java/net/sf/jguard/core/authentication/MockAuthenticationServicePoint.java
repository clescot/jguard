package net.sf.jguard.core.authentication;

import com.google.inject.Singleton;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;
import javax.security.auth.Subject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
@Singleton
public class MockAuthenticationServicePoint extends AbstractAuthenticationServicePoint<MockRequestAdapter, MockResponseAdapter> {

    private boolean authenticationSucceededDuringThisRequest;
    private Subject subject;


    private boolean enableHook = true;
    private final JGuardCallbackHandler guestCallbackHandler;

    @Inject
    public MockAuthenticationServicePoint(LoginContextWrapper loginContextWrapper,
                                          @Guest JGuardCallbackHandler guestCallbackHandler) {
        super(loginContextWrapper);
        this.guestCallbackHandler = guestCallbackHandler;
    }

    public boolean authenticationSucceededDuringThisRequest(MockRequestAdapter request, MockResponseAdapter response) {
        if (!enableHook) {
            return super.authenticationSucceededDuringThisRequest(request, response);
        }
        return authenticationSucceededDuringThisRequest;
    }

    public void setAuthenticationSucceededDuringThisRequest(boolean authenticationSucceededDuringThisRequest) {
        this.authenticationSucceededDuringThisRequest = authenticationSucceededDuringThisRequest;
    }

    public void setCurrentSubject(Subject subject) {
        this.subject = subject;
    }

    public Subject getSubject() {
        if (!enableHook) {
            return AbstractAuthenticationServicePoint.getCurrentSubject();
        }
        return subject;
    }

    public void setEnableHook(boolean enableHook) {
        this.enableHook = enableHook;
    }


    /**
     * impersonate the current user as a Guest user with the related credentials.
     * it set the NameCallback to <b>guest<b/>,the PasswordCallback to <b>guest</b>,
     * the InetAddressCallback host address and host name to 127.0.0.1 and localhost.
     * a wrapping mechanism for authenticationSchemeHandler and Scopes impersonate
     * the user as a guest, but the underlying statefulScopes contains the real user.
     * we put the guest Configuration to use a GuestAppConfigurationFilter, through a GuestConfiguration wrapper,
     * to not use loginModules which does not inherit from UserLoginModule,
     * and add a SKIP_CREDENTIAL_CHECK option to subclasses of UserLoginModules
     *
     * @return wrapper around the Guest Subject
     */
    public LoginContextWrapper impersonateAsGuest() {
        return authenticate(guestCallbackHandler);
    }
}
