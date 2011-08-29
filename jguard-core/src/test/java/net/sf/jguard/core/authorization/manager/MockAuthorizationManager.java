package net.sf.jguard.core.authorization.manager;

import net.sf.jguard.core.authorization.*;
import net.sf.jguard.core.authorization.permissions.JGPermissionCollection;
import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.authorization.permissions.MockPermission;
import net.sf.jguard.core.principals.RolePrincipal;

import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.Permission;
import java.util.*;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class MockAuthorizationManager implements AuthorizationManager {
    

    public void createPermission(net.sf.jguard.core.authorization.Permission url) throws AuthorizationManagerException {
    }

    public net.sf.jguard.core.authorization.Permission readPermission(long permissionId) throws AuthorizationManagerException {
        return null;
    }

    public void updatePermission(net.sf.jguard.core.authorization.Permission updatedPermission) throws AuthorizationManagerException {
    }

    public void deletePermission(net.sf.jguard.core.authorization.Permission permission) {
    }




    public List<net.sf.jguard.core.authorization.Permission> listPermissions() {
        return new ArrayList<net.sf.jguard.core.authorization.Permission>();
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

    public Set<net.sf.jguard.core.authorization.Permission> getPermissions(Collection<Long> permissionIds) {
        return null;
    }


    public void addToPrincipal(long roleId, net.sf.jguard.core.authorization.Permission perm) throws AuthorizationManagerException {
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
