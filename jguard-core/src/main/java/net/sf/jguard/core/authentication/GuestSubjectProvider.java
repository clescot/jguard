package net.sf.jguard.core.authentication;

import com.google.inject.Provider;
import com.google.inject.ProvisionException;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.technology.ImpersonationScopes;

import javax.inject.Inject;
import javax.security.auth.Subject;

public class GuestSubjectProvider implements Provider<Subject> {

    private static Subject subject = null;

    @Inject
    public GuestSubjectProvider(MockAuthenticationServicePoint authenticationServicePoint,
                                MockRequestAdapter request,
                                ImpersonationScopes impersonationScopes) {
        if (subject == null) {
            LoginContextWrapper wrapper = authenticationServicePoint.impersonateAsGuest(impersonationScopes);
            subject = wrapper.getSubject();
            if (null == subject) {
                throw new ProvisionException("provided subject is null");
            }
        }
    }

    public Subject get() {
        return subject;
    }
}
