package net.sf.jguard.core.authorization.permissions;

import org.junit.Assert;
import org.junit.Test;

import java.io.FilePermission;
import java.net.URL;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

public class AuditPermissionCollectionTest {

    @Test
    public void testImplies() {

        //initialize underlying permissionCollection
        PermissionCollection permissionCollection = new JGPositivePermissionCollection();
        URL url = Thread.currentThread().getContextClassLoader().getResource(".");
        Permission permission = new FilePermission(url.toExternalForm(), "read");
        permissionCollection.add(permission);
        Certificate[] certificates = new Certificate[]{};
        CodeSource codeSource = new CodeSource(url, certificates);
        ProtectionDomain protectionDomain = new ProtectionDomain(codeSource, permissionCollection);
        AuditPermissionCollection auditPermissionCollection = new AuditPermissionCollection(permissionCollection, protectionDomain);

        Assert.assertTrue(auditPermissionCollection.implies(permission));

    }
}
