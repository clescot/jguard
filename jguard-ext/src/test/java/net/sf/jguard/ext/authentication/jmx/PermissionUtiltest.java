package net.sf.jguard.ext.authentication.jmx;

import junit.framework.TestCase;
import org.junit.Test;

import java.security.Permission;

public class PermissionUtiltest {

    @Test
    public void testCreateMBeanPermissionTest() {
        Permission perm = null;
        try {
            perm = net.sf.jguard.core.authorization.Permission.getPermission(javax.management.MBeanPermission.class, "*", "*");
        } catch (ClassNotFoundException e) {
            TestCase.fail(e.getMessage());
        }
        System.out.println(perm.getName());
    }
}
