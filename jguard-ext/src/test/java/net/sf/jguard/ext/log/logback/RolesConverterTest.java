package net.sf.jguard.ext.log.logback;

import net.sf.jguard.core.authorization.permissions.RolePrincipal;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.Subject;
import java.security.PrivilegedAction;

public class RolesConverterTest {


    @Test
    public void test_convert_with_no_authentication() {
        RolesConverter converter = new RolesConverter();
        String convertedString = converter.convert(null);
        Assert.assertEquals(RolesConverter.NO_ROLES, convertedString);

    }


    @Test
    public void test_convert_with_authentication_and_no_roles() {
        Subject subject = new Subject();
        String convertedString = Subject.doAs(subject, new PrivilegedAction<String>() {
            public String run() {
                RolesConverter converter = new RolesConverter();
                return converter.convert(null);
            }
        });
        Assert.assertEquals(RolesConverter.NO_ROLES, convertedString);
    }

    @Test
    public void test_convert_with_authentication_and_1_role() {
        Subject subject = new Subject();
        subject.getPrincipals().add(new RolePrincipal("admin", "app"));

        String convertedString = Subject.doAs(subject, new PrivilegedAction<String>() {
            public String run() {
                RolesConverter converter = new RolesConverter();
                return converter.convert(null);
            }
        });
        Assert.assertEquals("app#admin", convertedString);
    }

    @Test
    public void test_convert_with_authentication_and_2_roles() {
        Subject subject = new Subject();
        subject.getPrincipals().add(new RolePrincipal("admin", "app"));
        subject.getPrincipals().add(new RolePrincipal("manager", "app"));

        String convertedString = Subject.doAs(subject, new PrivilegedAction<String>() {
            public String run() {
                RolesConverter converter = new RolesConverter();
                return converter.convert(null);
            }
        });
        Assert.assertEquals("app#admin,app#manager", convertedString);
    }
}
