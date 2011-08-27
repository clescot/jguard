package net.sf.jguard.core.authorization;

import org.junit.Test;

public class PermissionTest {


    @Test(expected = IllegalArgumentException.class)
    public void testGetPermission() throws ClassNotFoundException {
        Permission.getPermission(String.class,"toto","weirdActions");
    }
}
