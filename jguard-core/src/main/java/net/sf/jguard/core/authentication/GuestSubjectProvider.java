package net.sf.jguard.core.authentication;

import com.google.inject.Provider;
import com.google.inject.ProvisionException;

import javax.inject.Inject;
import javax.security.auth.Subject;

public class GuestSubjectProvider implements Provider<Subject> {

    private static Subject subject = null;

    @Inject
    public GuestSubjectProvider(MockAuthenticationServicePoint authenticationServicePoint) {
        if (subject == null) {
            LoginContextWrapper wrapper = authenticationServicePoint.impersonateAsGuest();
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
