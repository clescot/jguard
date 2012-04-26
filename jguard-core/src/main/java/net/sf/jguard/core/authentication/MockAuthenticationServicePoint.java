package net.sf.jguard.core.authentication;

import com.google.inject.Singleton;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.technology.ImpersonationScopes;
import net.sf.jguard.core.technology.MockScopes;

import javax.inject.Inject;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import java.util.List;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
@Singleton
public class MockAuthenticationServicePoint extends AbstractAuthenticationServicePoint<MockRequest, MockResponse> {

    private boolean authenticationSucceededDuringThisRequest;
    private Subject subject;


    private boolean enableHook = true;
    private final Configuration guestConfiguration;
    private final JGuardCallbackHandler guestCallbackHandler;

    @Inject
    public MockAuthenticationServicePoint(Configuration configuration,
                                          @Guest Configuration guestConfiguration,
                                          List<AuthenticationSchemeHandler<MockRequest, MockResponse>> authenticationSchemeHandlers,
                                          @ApplicationName String applicationName,
                                          MockScopes authenticationBindings,
                                          @Guest JGuardCallbackHandler guestCallbackHandler) {
        super(configuration,
                authenticationSchemeHandlers,
                applicationName,
                authenticationBindings);
        this.guestConfiguration = guestConfiguration;
        this.guestCallbackHandler = guestCallbackHandler;
    }

    public boolean authenticationSucceededDuringThisRequest(Request<MockRequest> request, Response<MockResponse> response) {
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

    public Subject getCurrentSubject() {
        if (!enableHook) {
            return super.getCurrentSubject();
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
     * the user as a guest, but the underlying authenticationBindings contains the real user.
     * we put the guest Configuration to use a GuestAppConfigurationFilter, through a GuestConfiguration wrapper,
     * to not use loginModules which does not inherit from UserLoginModule,
     * and add a SKIP_CREDENTIAL_CHECK option to subclasses of UserLoginModules
     *
     * @param impersonationScopes
     * @return wrapper around the Guest Subject
     */
    public LoginContextWrapper impersonateAsGuest(ImpersonationScopes impersonationScopes) {
        return authenticate(guestConfiguration, impersonationScopes, guestCallbackHandler);
    }
}
