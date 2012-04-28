package net.sf.jguard.core.authorization.filters;

import com.mycila.testing.junit.MycilaJunitRunner;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapper;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;
import net.sf.jguard.core.lifecycle.Request;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.inject.Inject;
import javax.security.auth.Subject;
import java.security.AccessControlException;
import java.security.Permission;
import java.security.PrivilegedAction;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(MycilaJunitRunner.class)
public class PolicyDecisionPointTest extends AuthorizationFilterTest {

    @Inject
    MockPolicyDecisionPoint policyDecisionPoint;

    @Inject
    AccessControllerWrapperImpl accessControlWrapper;

    @Before
    public void setUp() {
        super.setUp(policyDecisionPoint);
    }

    @Test
    public void test_doFilter_method_when_access_is_granted() {

        Subject subject = new Subject();
        executePolicyDecisionPoint(subject);
        verify(afterFilter).doFilter(any(MockRequestAdapter.class), any(MockResponseAdapter.class), any(FilterChain.class));
    }

    private void executePolicyDecisionPoint(Subject subject) {
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            public Object run() {
                policyDecisionPoint.doFilter(request, response, policyEnforcementPoint);
                return null;
            }
        });
    }

    @Test(expected = AccessControlException.class)
    public void test_doFilter_method_when_access_is_not_granted() {
        Subject subject = new Subject();
        AccessControllerWrapper accessControllerWrapper = mock(AccessControllerWrapper.class);
        policyDecisionPoint.setAccessControlWrapper(accessControllerWrapper);
        AuthorizationBindings authorizationBindings = mock(AuthorizationBindings.class);
        when(authorizationBindings.getPermissionRequested(any(Request.class))).thenReturn(notGrantedPermission);
        policyDecisionPoint.setAuthorizationBindings(authorizationBindings);
        when(accessControllerWrapper.hasPermission(any(Subject.class), any(Permission.class))).thenReturn(Boolean.FALSE);
        executePolicyDecisionPoint(subject);
        verify(afterFilter, never()).doFilter(any(MockRequestAdapter.class), any(MockResponseAdapter.class), any(FilterChain.class));
    }
}
