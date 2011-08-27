package net.sf.jguard.core.authorization.manager;

import net.sf.jguard.core.authorization.*;
import net.sf.jguard.core.authorization.permissions.JGPermissionCollection;
import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.authorization.permissions.MockPermission;
import net.sf.jguard.core.principals.RolePrincipal;

import java.security.*;
import java.security.Permission;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class MockAuthorizationManager implements AuthorizationManager {
    

    public void createPermission(net.sf.jguard.core.authorization.Permission url) throws AuthorizationManagerException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public net.sf.jguard.core.authorization.Permission readPermission(long permissionId) throws AuthorizationManagerException {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void updatePermission(net.sf.jguard.core.authorization.Permission updatedPermission) throws AuthorizationManagerException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void deletePermission(net.sf.jguard.core.authorization.Permission permission) {
        //To change body of implemented methods use File | Settings | File Templates.
    }




    public JGPermissionCollection listPermissions() {
        return new JGPositivePermissionCollection();
    }


    public void createPrincipal(RolePrincipal principal) throws AuthorizationManagerException {

    }

   

    public Principal readPrincipal(long roleId) throws AuthorizationManagerException {
        return null;
    }



    public void deletePrincipal(RolePrincipal principal) throws AuthorizationManagerException {

    }

    public Set<RolePrincipal> listPrincipals() {
        return null;
    }

    public Set<net.sf.jguard.core.authorization.Permission> getPermissions(Collection permissionNames) {
        return null;
    }


    public void addToPrincipal(long roleId, net.sf.jguard.core.authorization.Permission perm) throws AuthorizationManagerException {
    }




    public void addInheritance(long roleAscName, long roleDescName) throws AuthorizationManagerException {

    }

    public void deleteInheritance(String roleAscName, String roleDescName) throws AuthorizationManagerException {

    }

    public void updatePrincipal(RolePrincipal principal) throws AuthorizationManagerException {

    }



    public Set<RolePrincipal> getPrincipalsSet() {
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
