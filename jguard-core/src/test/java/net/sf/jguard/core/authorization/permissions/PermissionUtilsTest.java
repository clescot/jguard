package net.sf.jguard.core.authorization.permissions;

import net.sf.ehcache.CacheManager;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import java.io.FilePermission;
import java.net.URL;
import java.security.Permission;

import static org.junit.Assert.assertNotNull;


/**
 * test {@link net.sf.jguard.core.authorization.permissions.PermissionUtils} with dependencies
 * towards jguard-extras in its use.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class PermissionUtilsTest {
    private static final String UNKNOWN_CLASS_NAME = "unknownClassName";
    private static final String DUMMY_PERMISSION_NAME = "dummyPermissioNName";
    private static final String DUMMY_PERMISSION_ACTIONS = "dummyPermissionActions";


    @Test
    public void testGetPermission() throws ClassNotFoundException {
        URL url = Thread.currentThread().getContextClassLoader().getResource(".");
        Permission permission = net.sf.jguard.core.authorization.permissions.Permission.getPermission(FilePermission.class, url.toExternalForm(), "read");
        assertNotNull(permission);
    }


    @Test(expected = ClassNotFoundException.class)
    public void testGetPermissionWithUNknownClass() throws ClassNotFoundException {
        net.sf.jguard.core.authorization.permissions.Permission.getPermission(Class.forName(UNKNOWN_CLASS_NAME), DUMMY_PERMISSION_NAME, DUMMY_PERMISSION_ACTIONS);
    }

    @Test
    public void testCreateCaches() {
        PermissionUtils.createCaches();
        Assert.assertTrue(PermissionUtils.isCachesEnabled());
    }

    @Test
    public void testisCacheEnabled() {
        PermissionUtils.setCachesEnabled(false);
        Assert.assertFalse(PermissionUtils.isCachesEnabled());
        PermissionUtils.createCaches();
        Assert.assertTrue(PermissionUtils.isCachesEnabled());
    }

    @After
    public void tearsDown() {
        CacheManager.getInstance().shutdown();
    }

}
