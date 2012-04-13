package net.sf.jguard.core.authorization.policy;

import java.security.*;

/**
 * policy implementation for test-only purpose.
 */
public class AllAccessPolicy extends Policy {
    private PermissionCollection allPermissionCollection = new AllPermission(null, null).newPermissionCollection();

    @Override
    public PermissionCollection getPermissions(CodeSource codesource) {
        return allPermissionCollection;
    }

    @Override
    public PermissionCollection getPermissions(ProtectionDomain domain) {
        return allPermissionCollection;
    }

    @Override
    public boolean implies(ProtectionDomain domain, Permission permission) {
        return true;
    }
}
