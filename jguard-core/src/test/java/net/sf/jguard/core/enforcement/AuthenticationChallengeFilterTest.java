package net.sf.jguard.core.enforcement;

import com.google.inject.Inject;
import com.mycila.testing.junit.MycilaJunitRunner;
import net.sf.jguard.core.authentication.filters.AuthenticationChallengeFilter;
import net.sf.jguard.core.filters.Filter;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.test.FilterTest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
@RunWith(MycilaJunitRunner.class)
public class AuthenticationChallengeFilterTest extends FilterTest {

    @Inject
    AuthenticationChallengeFilter<MockRequest, MockResponse> challengeFilter;

    @Before
    public void setUp() {
        super.setUp(challengeFilter);
    }


    @Test
    public void test_that_filter_authenticate_when_user_answer_to_challenge_and_set_a_subject() {
        //will use the real authenticationServicePoint
        authenticationServicePoint.setEnableHook(false);

        Assert.assertNull(authenticationServicePoint.getCurrentSubject());
        policyEnforcementPoint.doFilter(request, response);
        //current subject is null because authentication succeed, and  does NOT implements StatefulScopes (that's a subcass of AbstractAuthenticationServicePOint,
        //and NOT StatefulAuthenticationServicePoint
        //so subject is put in the session, and can be grabbed anytime
        Assert.assertNull(authenticationServicePoint.getCurrentSubject());
    }


    @Test
    public void test_current_subject_is_not_null_in_filter() {
        policyEnforcementPoint.getFilters().add(new Filter<MockRequest, MockResponse>() {
            public void doFilter(Request<MockRequest> mockRequestRequest, Response<MockResponse> mockResponseResponse, FilterChain<MockRequest, MockResponse> mockRequestMockResponseFilterChain) {
                //we use the regular code and not the HOOK one
                authenticationServicePoint.setEnableHook(false);
                Assert.assertNotNull(authenticationServicePoint.getCurrentSubject());
            }
        });
        policyEnforcementPoint.doFilter(request, response);
    }


    @Test
    public void test_that_filter_pass_through_when_user_does_not_answer_to_a_challenge() {
        schemeHandler.setAnswerToChallenge(false);
        schemeHandler.setChallengeNeeded(true);
        policyEnforcementPoint.doFilter(request, response);
        Assert.assertNull(authenticationServicePoint.getCurrentSubject());
    }


}
