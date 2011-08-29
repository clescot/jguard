/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name$
http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles GAY

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


jGuard project home page:
http://sourceforge.net/projects/jguard/

*/
package net.sf.jguard.core.authorization.manager;

import net.sf.jguard.core.authorization.Permission;
import net.sf.jguard.core.authorization.permissions.JGPermissionCollection;
import net.sf.jguard.core.principals.RolePrincipal;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Set;


/**
 * retrieve user's permissions.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @author <a href="mailto:vinipitta@users.sourceforge.net">Vinicius Pitta Lima de Araujo</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
public interface AuthorizationManager extends PermissionProvider {



    /**
     * create an URLPermission giving a url and a domain
     *
     * @param url
     * @throws AuthorizationManagerException
     */
    void createPermission(Permission url) throws AuthorizationManagerException;

    Permission readPermission(long permissionId) throws AuthorizationManagerException;

    void updatePermission(Permission updatedPermission) throws AuthorizationManagerException;

    /**
     *
     * @param permission pemrission to delete
     * @throws IllegalArgumentException when the permisison to delete is not present in the datastore
     */
    void deletePermission(Permission permission) ;

    void createPrincipal(RolePrincipal principal) throws AuthorizationManagerException;

    List<Permission> listPermissions();


    RolePrincipal readPrincipal(long roleId) throws AuthorizationManagerException;

    void deletePrincipal(RolePrincipal principal) throws AuthorizationManagerException;

    /**
     * return the modifable Principal Set.
     * @return
     */
    List<RolePrincipal> listPrincipals();

    Set<Permission> getPermissions(Collection<Long> permissionIds);

    void addToPrincipal(long roleId, Permission perm) throws AuthorizationManagerException;


    /* RBAC Role General Hierarchical model specific methods */

    /**
     * This commands establishes a new immediate inheritance relationship
     * between the existing principals roleAsc and the roleDesc.
     * The command is valid if and only if the role roleAsc is not an immediate
     * ascendant of roleDesc, and descendant does
     * not properly inherit roleAsc role (in order to avoid cycle creation).
     *
     * @param roleAscId  the role that will inherite.
     * @param roleDescId the role that will be inherited.
     * @throws AuthorizationManagerException if the inheritance already exists or create a cycle.
     */
    void addInheritance(long roleAscId, long roleDescId) throws AuthorizationManagerException;

    /**
     * Delete the existing inheritance beteween roleAsc and roleDesc.
     *
     * @param roleAscId
     * @param roleDescId
     * @throws AuthorizationManagerException
     */
    void deleteInheritance(Long roleAscId, Long roleDescId) throws AuthorizationManagerException;

    /**
     * replace the inital principal with the new one.
     *
     * @param principal RolePrincipal updated
     * @throws AuthorizationManagerException
     */
    void updatePrincipal(RolePrincipal principal) throws AuthorizationManagerException;

    boolean isEmpty();

    void importAuthorizationManager(AuthorizationManager authorizationManager) throws AuthorizationManagerException;

    /**
     * define the name of the <strong>current</strong> application which holds this
     * AuthorizationManager.
     *
     * @return
     */
    String getApplicationName();

    boolean isNegativePermissions();

    public boolean isPermissionResolutionCaching();

    String exportAsXMLString() throws AuthorizationManagerException;

    void writeAsHTML(OutputStream outputStream) throws IOException, AuthorizationManagerException;

    void writeAsXML(OutputStream outputStream, String encodingScheme) throws IOException, AuthorizationManagerException;

    void exportAsXMLFile(String fileName) throws IOException, AuthorizationManagerException;
}
