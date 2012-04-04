package net.sf.jguard.core.authorization;

import net.sf.jguard.core.authorization.permissions.Permission;
import org.junit.Test;

public class PermissionTest {


    @Test(expected = IllegalArgumentException.class)
    public void testGetPermission() throws ClassNotFoundException {
        Permission.getPermission(String.class, "toto", "weirdActions");
    }
}
