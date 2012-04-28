package net.sf.jguard.core.authentication.filters;

import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.Guest;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;
import javax.security.auth.Subject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockGuestAuthenticationFilter extends GuestAuthenticationFilter<MockRequestAdapter, MockResponseAdapter> {
    @Inject
    public MockGuestAuthenticationFilter(@Guest Subject subject,
                                         AuthenticationServicePoint<MockRequestAdapter, MockResponseAdapter> authenticationServicePoint) {
        super(subject, authenticationServicePoint);
    }
}
