package net.sf.jguard.core.authentication.filters;

import com.google.inject.Inject;
import com.mycila.testing.junit.MycilaJunitRunner;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.*;
import net.sf.jguard.core.test.FilterTest;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.security.auth.Subject;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
@RunWith(MycilaJunitRunner.class)
public class GuestAuthenticationFilterTest extends FilterTest {

    @Inject
    private MockGuestAuthenticationFilter authenticationFilter;


    @Test
    public void test_no_guest_authentication_when_subject_is_already_present_in_session() {
        MockRequest request = new MockRequest();
        Request<MockRequest> requestAdapter = new MockRequestAdapter(request);
        MockResponse response = new MockResponse();
        Response<MockResponse> responseAdapter = new MockResponseAdapter(response);
        FilterChain filterChain = new FilterChain() {
            public void doFilter(Request request, Response response) {

            }
        };
        Subject subject = authenticationServicePoint.getCurrentSubject();
        Assert.assertNull(subject);
        authenticationFilter.doFilter(requestAdapter, responseAdapter, filterChain);
        Assert.assertNull(authenticationServicePoint.getCurrentSubject());
        Assert.assertSame(subject, authenticationServicePoint.getCurrentSubject());

    }


}
