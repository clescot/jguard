package net.sf.jguard.core.authentication;

import com.google.inject.Singleton;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
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

    @Inject
    public MockAuthenticationServicePoint(Configuration configuration,
                                          @Guest Configuration guestConfiguration,
                                          List<AuthenticationSchemeHandler<MockRequest, MockResponse>> authenticationSchemeHandlers,
                                          @ApplicationName String applicationName,
                                          MockScopes authenticationBindings,
                                          @Guest JGuardCallbackHandler guestCallbackHandler) {
        super(configuration,
                guestConfiguration,
                authenticationSchemeHandlers,
                applicationName,
                authenticationBindings, guestCallbackHandler);
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
}
