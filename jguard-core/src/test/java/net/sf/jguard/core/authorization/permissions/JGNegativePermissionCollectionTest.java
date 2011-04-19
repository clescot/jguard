package net.sf.jguard.core.authorization.permissions;

import junit.framework.TestCase;

import java.net.URISyntaxException;
import java.security.Permission;

public class JGNegativePermissionCollectionTest extends TestCase {

    public void testImplies() throws URISyntaxException {

        // Mock permissions
        JGPermissionCollection jgperm = new JGNegativePermissionCollection();
        Permission p1 = new URLPermission("mock_perm_1", "/someuri_1.do");
        Permission p2 = new URLPermission("mock_perm_2", "/someuri_2.do");
        Permission p3 = new URLPermission("mock_perm_3", "/someuri_1.do?param1=abcde");
        Permission p4 = new URLPermission("mock_perm_4", "/someuri_4.do");

        // Add some implied and not implied
        jgperm.add(p1);
        jgperm.add(p2);

        // Testing
        assertFalse(jgperm.implies(p3));
        assertTrue(jgperm.implies(p4));
    }

}
