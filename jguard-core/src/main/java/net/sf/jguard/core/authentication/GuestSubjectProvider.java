package net.sf.jguard.core.authentication;

import com.google.inject.Provider;
import com.google.inject.ProvisionException;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;

import javax.inject.Inject;
import javax.security.auth.Subject;

public class GuestSubjectProvider implements Provider<Subject> {

    private static Subject subject = null;

    @Inject
    public GuestSubjectProvider(MockAuthenticationServicePoint authenticationServicePoint,
                                MockRequestAdapter request) {
        if (subject == null) {
            LoginContextWrapper wrapper = authenticationServicePoint.impersonateAsGuest(request);
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
