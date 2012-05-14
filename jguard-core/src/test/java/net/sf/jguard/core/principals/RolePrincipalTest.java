package net.sf.jguard.core.principals;

import net.sf.jguard.core.authorization.permissions.MockPermission;
import net.sf.jguard.core.authorization.permissions.Permission;
import net.sf.jguard.core.authorization.permissions.RolePrincipal;
import org.junit.Test;

import java.io.FilePermission;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class RolePrincipalTest {

    @Test
    public void testClone() throws CloneNotSupportedException {
        RolePrincipal rolePrincipal = new RolePrincipal("myrole");
        RolePrincipal clonedRolePrincipal = (RolePrincipal) rolePrincipal.clone();

    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorsWithOneNullParameter() {
        RolePrincipal rolePrincipal = new RolePrincipal(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorsWithOneEmptyParameter() {
        RolePrincipal rolePrincipal = new RolePrincipal("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorsWithtwoNullParameter() {
        RolePrincipal rolePrincipal = new RolePrincipal(null, (String) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorsWithtwoEmptyParameter() {
        RolePrincipal rolePrincipal = new RolePrincipal("", "");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorsWithOneFilledAndOneEmptyParameter() {
        RolePrincipal rolePrincipal = new RolePrincipal("zeze", "");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorsWithOneEmptyAndOneFilledParameter() {
        RolePrincipal rolePrincipal = new RolePrincipal("", "zeze");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorsWithOneNullAndOneFilledParameter() {
        RolePrincipal rolePrincipal = new RolePrincipal(null, "zeze");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorsWithOneFilledAndOneNullParameter() {
        RolePrincipal rolePrincipal = new RolePrincipal("zeze", (String) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructors1() {
        RolePrincipal rolePrincipal = new RolePrincipal(null, (String) null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructors2() {
        RolePrincipal rolePrincipal = new RolePrincipal("", (String) null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructors3() {
        RolePrincipal rolePrincipal = new RolePrincipal("", "", null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructors4() {
        RolePrincipal rolePrincipal = new RolePrincipal("", "", new Organization());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructors5() {
        RolePrincipal rolePrincipal = new RolePrincipal("sdfsd", "", new Organization());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testTranslateToJGuardPermission_with_null_argument() {
        RolePrincipal.translateToJGuardPermission(null);
    }

    @Test
    public void testTranslateToJGuardPermission_with_permission() {
        //when
        Permission permission = RolePrincipal.translateToJGuardPermission(new FilePermission("/", "read"));
        //then
        assertThat(permission, is(not(nullValue())));

    }


    @Test
    public void testTranslateToJGuardPermission_with_permission_with_a_name_and_null_actions() {
        //when
        Permission permission = RolePrincipal.translateToJGuardPermission(new MockPermission("/", null));
        //then
        assertThat(permission, is(not(nullValue())));

    }


}
