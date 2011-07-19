package net.sf.jguard.core.authorization.manager;

import net.sf.jguard.core.authorization.permissions.JGPermissionCollection;
import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.authorization.permissions.MockPermission;

import java.security.*;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class MockAuthorizationManager implements AuthorizationManager {
    public List getInitParameters() {
        return null;
    }

    public void createPermission(Permission url) throws AuthorizationManagerException {

    }

    public Permission readPermission(String permissionName) throws AuthorizationManagerException {
        return null;
    }

    public void updatePermission(String oldPermissionName, Permission updatedPermission) throws AuthorizationManagerException {

    }

    public void deletePermission(String permissionName) throws AuthorizationManagerException {

    }

    public JGPermissionCollection listPermissions() {
        return new JGPositivePermissionCollection();
    }


    public void createPrincipal(Principal principal) throws AuthorizationManagerException {

    }

    public Principal clonePrincipal(String roleName) throws AuthorizationManagerException {
        return null;
    }

    public Principal clonePrincipal(String roleName, String cloneName) throws AuthorizationManagerException {
        return null;
    }

    public Principal readPrincipal(String roleName) throws AuthorizationManagerException {
        return null;
    }

    public void updatePrincipal(String oldPrincipalName, Principal principal) throws AuthorizationManagerException {

    }

    public void deletePrincipal(Principal principal) throws AuthorizationManagerException {

    }

    public Set listPrincipals() {
        return null;
    }


    public Set<Permission> getPermissions(Collection permissionNames) {
        return null;
    }

    public void addToPrincipal(String roleName, Permission perm) throws AuthorizationManagerException {

    }



    public void addInheritance(String roleAscName, String roleDescName) throws AuthorizationManagerException {

    }

    public void deleteInheritance(String roleAscName, String roleDescName) throws AuthorizationManagerException {

    }

    public void updatePrincipal(Principal principal) throws AuthorizationManagerException {

    }



    public Set<Principal> getPrincipalsSet() {
        return null;
    }

    public Set<Permission> getPermissionsSet() {
        return null;
    }

    public boolean isEmpty() {
        return false;
    }

    public void importAuthorizationManager(AuthorizationManager authorizationManager) throws AuthorizationManagerException {

    }

    public String getApplicationName() {
        return null;
    }

    public boolean isNegativePermissions() {
        return false;
    }

    public boolean isPermissionResolutionCaching() {
        return true;
    }

    public PermissionCollection getPermissions(ProtectionDomain pDomain) {
        JGPositivePermissionCollection collection = new JGPositivePermissionCollection();
        collection.add(new MockPermission("mock"));
        return collection;

    }

    public void refresh() {

    }

    public void addAlwaysGrantedPermissions(Permissions permissions) {

    }
}
