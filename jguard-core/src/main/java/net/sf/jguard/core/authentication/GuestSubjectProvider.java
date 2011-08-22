package net.sf.jguard.core.authentication;

import javax.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.ProvisionException;
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
            if(null==subject){
                throw new ProvisionException("provided subject is null");
            }
            authenticationBindings.setApplicationAttribute(SubjectUtils.GUEST_SUBJECT, subject);
        }
    }

    public Subject get() {
        return subject;
    }
}
