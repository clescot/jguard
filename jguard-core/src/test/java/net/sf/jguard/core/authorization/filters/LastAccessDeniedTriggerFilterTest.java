package net.sf.jguard.core.authorization.filters;

import com.mycila.testing.junit.MycilaJunitRunner;
import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.LoginContextWrapperImpl;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;
import net.sf.jguard.core.lifecycle.StatefulRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.inject.Inject;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import java.security.Permission;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(MycilaJunitRunner.class)
public class LastAccessDeniedTriggerFilterTest extends AuthorizationFilterTest {


    public static final String DUMMY_APPLICATION_NAME = "applicationName";
    @Inject
    MockLastAccessDeniedTriggerFilter filter;


    Subject authenticatedSubject;

    @Before
    public void setUp() {
        super.setUp(filter);
        authenticatedSubject = new Subject();
    }


    @Test
    public void test_doFilter_when_authentication_succeed_and_lastAccessDeniedPermission_is_null() {
        authenticationServicePoint.setAuthenticationSucceededDuringThisRequest(true);
        putSubjectIntoSession(request);
        AuthorizationBindings<MockRequestAdapter, MockResponseAdapter> authorizationBindings = mock(AuthorizationBindings.class);
        filter.setAuthorizationBindings(authorizationBindings);


        when(authorizationBindings.getPostAuthenticationPermission(any(MockRequestAdapter.class))).thenReturn(grantedPermission);

        policyEnforcementPoint.doFilter(request, response);

        //we test that lastAccessDeniedFilter call authorizationBindings.handlePermission with postAuthenticationSucceed Permission.
        //and call filterChain.doFilter()
        verify(authorizationBindings).handlePermission(any(MockRequestAdapter.class), any(MockResponseAdapter.class), eq(grantedPermission));
    }

    @Test
    public void test_doFilter_when_authentication_succeed_and_lastAccessDeniedPermission_is__not_null_but_not_granted() {
        //given
        authenticationServicePoint.setAuthenticationSucceededDuringThisRequest(true);
        putSubjectIntoSession(request);
        AuthorizationBindings<MockRequestAdapter, MockResponseAdapter> authorizationBindings = mock(AuthorizationBindings.class);
        filter.setAuthorizationBindings(authorizationBindings);
        when(authorizationBindings.getPostAuthenticationPermission(any(MockRequestAdapter.class))).thenReturn(grantedPermission);

        //when
        policyEnforcementPoint.doFilter(request, response);

    }


    @Test
    public void test_doFilter_when_authentication_succeed_and_lastAccessDeniedPermission_is__not_null_and_granted() {
        //given
        authenticationServicePoint.setAuthenticationSucceededDuringThisRequest(true);
        putSubjectIntoSession(request);
        AuthorizationBindings<MockRequestAdapter, MockResponseAdapter> authorizationBindings = mock(AuthorizationBindings.class);
        filter.setAuthorizationBindings(authorizationBindings);
        when(authorizationBindings.getPostAuthenticationPermission(any(MockRequestAdapter.class))).thenReturn(grantedPermission);

        //when
        policyEnforcementPoint.doFilter(request, response);
    }

    @Test
    public void test_doFilter_when_authentication_has_not_be_done_during_this_request() {
        authenticationServicePoint.setAuthenticationSucceededDuringThisRequest(false);
        AuthorizationBindings<MockRequestAdapter, MockResponseAdapter> authorizationBindings = mock(AuthorizationBindings.class);
        //when
        policyEnforcementPoint.doFilter(request, response);

        //then
        verify(authorizationBindings, never()).handlePermission(any(MockRequestAdapter.class), any(MockResponseAdapter.class), any(Permission.class));
    }

    private void putSubjectIntoSession(StatefulRequest request) {
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(DUMMY_APPLICATION_NAME, mock(Configuration.class)) {
            public Subject getSubject() {
                return authenticatedSubject;
            }

        };
        request.setSessionAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER, loginContextWrapper);
    }

}
