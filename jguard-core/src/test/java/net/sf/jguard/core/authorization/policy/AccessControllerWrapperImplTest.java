package net.sf.jguard.core.authorization.policy;

import net.sf.jguard.core.authorization.manager.MockAuthorizationManager;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.security.auth.Subject;
import java.security.AccessControlException;
import java.security.AllPermission;
import java.security.Permission;
import java.security.Permissions;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;


public class AccessControllerWrapperImplTest {

    private SingleAppPolicy policy = new SingleAppPolicy(new MockAuthorizationManager(), new Permissions());

    @Mock
    LocalAccessController localAccessController;

    @InjectMocks
    private AccessControllerWrapperImpl accessControllerWrapper = new AccessControllerWrapperImpl(policy);

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testHasPermission_nominal_case() throws Exception {

        //when
        accessControllerWrapper.hasPermission(new Subject(), new AllPermission());

    }

    @Test
    public void testHasPermission_with_internal_exception() throws Exception {
        //given
        doThrow(new AccessControlException("name")).when(localAccessController).checkPermission(any(Permission.class));

        //when
        boolean hasPermission = accessControllerWrapper.hasPermission(new Subject(), new AllPermission());

        //then
        assertThat(hasPermission, is(false));

    }


    @Test
    public void testCheckPermission() throws Exception {

    }
}
