package net.sf.jguard.core.authorization.policy;

import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.core.principals.Organization;
import net.sf.jguard.core.principals.RolePrincipal;
import org.junit.Test;

import javax.security.auth.Subject;
import java.io.FilePermission;
import java.security.AccessControlException;
import java.security.Permission;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import static org.junit.Assert.fail;

public class LocalAccessControllerTest {

    final Permission permission = new URLPermission("name");

    @Test
    public void testCheckPermission() throws PrivilegedActionException {
        final LocalAccessController accessController = getLocalAccessController();


        final Subject subject = new Subject();
        Organization orga = new Organization();
        RolePrincipal principal = new RolePrincipal("dummy", "myapp", orga);
        principal.addPermission(permission);
        subject.getPrincipals().add(principal);

        try {
            Subject.doAsPrivileged(subject, new PrivilegedExceptionAction() {
                public Object run() {
                    //we wrap the ServletRequest to 'correct' the j2ee's JAAS handling
                    // according to the j2se way
                    accessController.checkPermission(permission);
                    // the 'null' tells the SecurityManager to consider this resource access
                    //in an isolated context, ignoring the permissions of code currently
                    //on the execution stack.
                    return null;
                }
            }, null);
        } catch (AccessControlException ace) {
            fail(" user is not granted although if he has got the right permission ");
        }
        final Permission permission2 = new FilePermission("/toto", "delete");
        try {
            Subject.doAsPrivileged(subject, new PrivilegedExceptionAction() {
                public Object run() {
                    //we wrap the ServletRequest to 'correct' the j2ee's JAAS handling
                    // according to the j2se way
                    accessController.checkPermission(permission2);
                    // the 'null' tells the SecurityManager to consider this resource access
                    //in an isolated context, ignoring the permissions of code currently
                    //on the execution stack.
                    return null;
                }
            }, null);
            fail(" user is granted although if he hasn't got the right permission ");
        } catch (AccessControlException ace) {
            //normal case
        }


    }

    private LocalAccessController getLocalAccessController() {
        DummyPolicy policy = new DummyPolicy();
        policy.addPermission(permission);
        final LocalAccessController accessController = new LocalAccessController(policy);
        return accessController;
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCheckPermissionWithNull() {
        LocalAccessController controller = getLocalAccessController();
        controller.checkPermission(null);
    }

}
