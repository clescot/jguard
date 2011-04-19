package net.sf.jguard.core.authorization.policy;

import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;

import java.security.*;

class DummyPolicy extends Policy {

    private PermissionCollection permColl = new JGPositivePermissionCollection();

    public void addPermission(Permission permission) {
        permColl.add(permission);
    }


    public PermissionCollection getPermissions(CodeSource codesource) {

        return permColl;
    }

    public void refresh() {
        // TODO Auto-generated method stub

    }


    public PermissionCollection getPermissions(ProtectionDomain domain) {
        return permColl;

    }
}
