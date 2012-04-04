package net.sf.jguard.core.authorization.manager;

import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.authorization.permissions.MockPermission;
import net.sf.jguard.core.authorization.permissions.Permission;
import net.sf.jguard.core.principals.RolePrincipal;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockAuthorizationManager implements AuthorizationManager {
    

    public void createPermission(Permission url) throws AuthorizationManagerException {
    }

    public Permission readPermission(long permissionId) throws AuthorizationManagerException {
        return null;
    }

    public void updatePermission(Permission updatedPermission) throws AuthorizationManagerException {
    }

    public void deletePermission(Permission permission) {
    }




    public List<Permission> listPermissions() {
        return new ArrayList<Permission>();
    }


    public void createPrincipal(RolePrincipal principal) throws AuthorizationManagerException {

    }

   

    public RolePrincipal readPrincipal(long roleId) throws AuthorizationManagerException {
        return null;
    }



    public void deletePrincipal(RolePrincipal principal) throws AuthorizationManagerException {

    }

    public List<RolePrincipal> listPrincipals() {
        return null;
    }

    public Set<Permission> getPermissions(Collection<Long> permissionIds) {
        return null;
    }


    public void addToPrincipal(long roleId, Permission perm) throws AuthorizationManagerException {
    }




    public void addInheritance(long roleAscName, long roleDescName) throws AuthorizationManagerException {

    }

    public void deleteInheritance(Long roleAscId, Long roleDescId) throws AuthorizationManagerException {

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

    public String exportAsXMLString() throws AuthorizationManagerException {
        return null;
    }

    public void writeAsHTML(OutputStream outputStream) throws IOException, AuthorizationManagerException {
    }

    public void writeAsXML(OutputStream outputStream, String encodingScheme) throws IOException, AuthorizationManagerException {
    }

    public void exportAsXMLFile(String fileName) throws IOException, AuthorizationManagerException {
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
