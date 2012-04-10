package net.sf.jguard.core.principals;

import java.security.Permission;
import java.util.Set;

public interface PermissionContainer extends BasePrincipal {


    /**
     * return all permissions owned by this Principal plus
     * permissions inherited from descendants.
     *
     * @return permissions
     */
    public Set<Permission> getAllPermissions();
}
