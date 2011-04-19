package net.sf.jguard.core.authentication;

import com.google.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;
import net.sf.jguard.core.technology.ImpersonationScopes;
import net.sf.jguard.core.technology.MockScopes;
import net.sf.jguard.core.util.SubjectUtils;

import javax.security.auth.Subject;

public class GuestSubjectProvider implements Provider<Subject> {

    private static Subject subject = null;

    @Inject
    public GuestSubjectProvider(MockAuthenticationServicePoint authenticationServicePoint,
                                MockRequestAdapter request,
                                MockResponseAdapter response,
                                MockScopes authenticationBindings,
                                ImpersonationScopes impersonationScopes) {
        if (subject == null) {
            LoginContextWrapper wrapper = authenticationServicePoint.impersonateAsGuest(request, response, impersonationScopes);
            subject = wrapper.getSubject();
            authenticationBindings.setApplicationAttribute(SubjectUtils.GUEST_SUBJECT, subject);
        }
    }

    public Subject get() {
        return subject;
    }
}
