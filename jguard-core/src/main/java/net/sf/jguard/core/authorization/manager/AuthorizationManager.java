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

import net.sf.jguard.core.authorization.permissions.JGPermissionCollection;

import java.security.Permission;
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
     * return needed initialization parameters.
     *
     * @return parameters list.
     */
    List getInitParameters();


    /**
     * create an URLPermission giving a url and a domain
     *
     * @param url
     * @throws AuthorizationManagerException
     */
    void createPermission(Permission url) throws AuthorizationManagerException;

    Permission readPermission(String permissionName) throws AuthorizationManagerException;

    void updatePermission(String oldPermissionName, Permission updatedPermission) throws AuthorizationManagerException;

    void deletePermission(String permissionName) throws AuthorizationManagerException;

    JGPermissionCollection listPermissions();

    void createPrincipal(Principal principal) throws AuthorizationManagerException;

    /**
     * Clone a Principal with a random name
     *
     * @param roleName Principal name to clone
     * @return cloned Principal with a different name: roleName + Random integer betweeen 0 and 99999
     * @throws AuthorizationManagerException
     */
    Principal clonePrincipal(String roleName) throws AuthorizationManagerException;

    /**
     * Clone a Principal. If Principal is instance of RolePrincipal makes a call to the clone method leting the clone task to RolePrincipal
     *
     * @param roleName  Principal name to clone
     * @param cloneName Principal cloned name
     * @return cloned Principal with the given cloneName
     * @throws AuthorizationManagerException
     */
    Principal clonePrincipal(String roleName, String cloneName) throws AuthorizationManagerException;

    Principal readPrincipal(String roleName) throws AuthorizationManagerException;

    /**
     * update the application Principal (role).
     *
     * @param oldPrincipalName the name the principal had
     * @param principal        the new principal updated
     * @throws AuthorizationManagerException
     */
    void updatePrincipal(String oldPrincipalName, Principal principal) throws AuthorizationManagerException;

    void deletePrincipal(Principal principal) throws AuthorizationManagerException;

    /**
     * return the modifable Principal Set.
     * @return
     */
    Set listPrincipals();

    Set<Permission> getPermissions(Collection permissionNames);

    void addToPrincipal(String roleName, Permission perm) throws AuthorizationManagerException;


    /* RBAC Role General Hierarchical model specific methods */

    /**
     * This commands establishes a new immediate inheritance relationship
     * between the existing principals roleAsc and the roleDesc.
     * The command is valid if and only if the role roleAsc is not an immediate
     * ascendant of roleDesc, and descendant does
     * not properly inherit roleAsc role (in order to avoid cycle creation).
     *
     * @param roleAscName  the role that will inherite.
     * @param roleDescName the role that will be inherited.
     * @throws AuthorizationManagerException if the inheritance already exists or create a cycle.
     */
    void addInheritance(String roleAscName, String roleDescName) throws AuthorizationManagerException;

    /**
     * Delete the existing inheritance beteween roleAsc and roleDesc.
     *
     * @param roleAscName
     * @param roleDescName
     * @throws AuthorizationManagerException
     */
    void deleteInheritance(String roleAscName, String roleDescName) throws AuthorizationManagerException;

    /**
     * replace the inital principal with the new one.
     *
     * @param principal RolePrincipal updated
     * @throws AuthorizationManagerException
     */
    void updatePrincipal(Principal principal) throws AuthorizationManagerException;

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
}
