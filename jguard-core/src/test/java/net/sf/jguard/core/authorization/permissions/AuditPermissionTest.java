package net.sf.jguard.core.authorization.permissions;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.FilePermission;
import java.net.URL;
import java.security.Permission;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class AuditPermissionTest {
    private Permission perm1;
    private Permission perm2;
    private Permission perm3;
    private Permission perm4;
    private Permission aperm1;
    private Permission aperm2;
    private Permission aperm3;
    private Permission aperm4;

    @Before
    public void setUp() {
        perm1 = new URLPermission("toto");
        perm2 = new URLPermission("toto");
        perm3 = new URLPermission("toto*");
        perm4 = new URLPermission("toto4", "blabla");
        aperm1 = new AuditPermission(perm1);
        aperm2 = new AuditPermission(perm2);
        aperm3 = new AuditPermission(perm3);
        aperm4 = new AuditPermission(perm4);
    }

    @Test
    public void testImplies() {

        Assert.assertTrue(perm1.implies(perm2));
        Assert.assertTrue(perm2.implies(perm1));
        Assert.assertTrue(perm3.implies(perm1));
        Assert.assertTrue(perm1.implies(perm3));

        Assert.assertTrue(aperm1.implies(aperm2));
        Assert.assertTrue(aperm2.implies(aperm1));
        Assert.assertFalse(aperm2.getName().equals(""));
        Assert.assertTrue(aperm3.implies(aperm1));
        Assert.assertTrue(aperm1.implies(aperm3));
        URL current = Thread.currentThread().getContextClassLoader().getResource(".");
        Permission permission = new FilePermission(current.toExternalForm(), "read");
        Assert.assertFalse(aperm1.implies(permission));

    }


    @Test
    public void testHashCode() {
        URL current = Thread.currentThread().getContextClassLoader().getResource(".");
        Permission permission = new FilePermission(current.toExternalForm(), "read");
        Assert.assertFalse(aperm1.hashCode() == permission.hashCode());
    }


    @Test
    public void testEquals() {

        Assert.assertTrue(perm1.equals(perm2));
        Assert.assertTrue(perm2.equals(perm1));
        Assert.assertTrue(aperm1.equals(aperm2));
        Assert.assertTrue(aperm2.equals(aperm1));
        Assert.assertFalse(aperm2.getName().equals(""));
        Assert.assertFalse(aperm3.equals(aperm1));
        Assert.assertFalse(aperm1.equals(aperm3));

        URL current = Thread.currentThread().getContextClassLoader().getResource(".");
        Permission permission = new FilePermission(current.toExternalForm(), "read");
        Assert.assertFalse(aperm1.equals(permission));
    }

    /**
     * we test that AuditPermission does not modify the underlying name
     * from the wrapped permission.
     */
    @Test
    public void testGetName() {
        Assert.assertTrue("toto".equals(aperm1.getName()));
        Assert.assertTrue("toto4".equals(aperm4.getName()));
    }

    @Test
    public void testActions() {
        Assert.assertTrue("blabla,ANY".equals(aperm4.getActions()));
    }

}
