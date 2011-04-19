package net.sf.jguard.ext.authentication.jmx;

import junit.framework.TestCase;
import net.sf.jguard.core.authorization.permissions.PermissionUtils;
import org.junit.Test;

import java.security.Permission;

public class PermissionUtiltest {

    @Test
    public void testCreateMBeanPermissionTest() {
        Permission perm = null;
        try {
            perm = PermissionUtils.getPermission("javax.management.MBeanPermission", "*", "*");
        } catch (ClassNotFoundException e) {
            TestCase.fail(e.getMessage());
        }
        System.out.println(perm.getName());
    }
}
