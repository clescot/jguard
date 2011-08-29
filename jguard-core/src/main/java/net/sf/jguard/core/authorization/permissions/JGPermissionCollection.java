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
package net.sf.jguard.core.authorization.permissions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Permission;
import java.security.PermissionCollection;
import java.util.*;


/**
 * contains similar permissions.
 * this class contains similar <strong>java.security.Permission</strong> instances,
 * with the same type.
 * it is a "technical" container in opposite to Domain,which is a "functional" container.
 * Classes extending this abstract class must implements implies method from PermissionCollection.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net ">Charles Gay</a>
 */
public abstract class JGPermissionCollection extends PermissionCollection {

    /**
     * serial version id.
     */
    private static final long serialVersionUID = 3834030277143377201L;
    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(JGPermissionCollection.class.getName());

    Set<Permission> permissions;

    /**
     * default constructor.
     */
    JGPermissionCollection() {

        permissions = new HashSet<Permission>();
    }

    /**
     * constructor.
     *
     * @param collection collection of {@link java.security.Permission}
     */
    JGPermissionCollection(Collection<Permission> collection) {

        permissions = new HashSet<Permission>(collection);
    }

    /**
     * add a permission to the set.
     *
     * @see java.security.PermissionCollection#add(java.security.Permission)
     */
    public void add(Permission permission) {
        if (permission != null) {
            permissions.add(permission);
        }else{
            throw new IllegalArgumentException("permission is null");
        }

    }

    /**
     * add permissions to the set.
     *
     * @param permissionSet
     * @see java.security.PermissionCollection#add(java.security.Permission)
     */
    public void addAll(Set<Permission> permissionSet) {
        if (permissionSet != null) {
            permissions.addAll(permissionSet);
        }

    }

    public void addAll(PermissionCollection pcColl) {
        Enumeration en = pcColl.elements();
        while (en.hasMoreElements()) {
            permissions.add((Permission) en.nextElement());
        }
    }

    /**
     * return all the permissions.
     *
     * @see java.security.PermissionCollection#elements()
     */
    public Enumeration<Permission> elements() {
        return Collections.enumeration(permissions);

    }


    /**
     * return the corresponding permission.
     *
     * @param permissionName
     * @return permission
     * @throws NoSuchPermissionException
     */
    public Permission getPermission(String permissionName) throws NoSuchPermissionException {
        Permission permission;
        for (Permission permission1 : permissions) {
            permission = permission1;
            if (permission.getName().equals(permissionName)) {
                return permission;
            }

        }
        logger.warn("permission " + permissionName + " not found in JGPermissionCollection#getPermission!!!");
        logger.warn("permissions=" + permissions);
        throw new NoSuchPermissionException("permission " + permissionName + " not found in JGPermissionCollection#getPermission");

    }

    /**
     * remove permission from Permission's collection.
     *
     * @param permission
     */
    public void removePermission(Permission permission) {
        if (permission != null) {
            permissions.remove(permission);
        }
    }

    /**
     * remove permission from Permission's collection.
     *
     * @param permColl
     */
    public void removePermissions(PermissionCollection permColl) {
        Enumeration<Permission> permissionsEnum = permColl.elements();
        while (permissionsEnum.hasMoreElements()) {
            permissions.remove(permissionsEnum.nextElement());
        }
    }

    /**
     * remove permission from Permission's collection.
     */
    public void clear() {
        permissions.clear();
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        for (Permission permission1 : this.permissions) {
            sb.append(permission1.toString());
            sb.append("\n");
        }
        return sb.toString();
    }

    /**
     * @return permissions number owned by this JgPermissionCollection.
     */
    public int size() {
        return permissions.size();
    }

    /**
     * @return Returns the permissions.
     */
    public Set<Permission> getPermissions() {
        return permissions;
    }

    /**
     * @param permission permission to check
     * @return
     */
    public boolean containsPermission(Permission permission) {
        return permissions.contains(permission);
    }

    /**
     * @param perms The permissions to set.
     */
    void setPermissions(Set<Permission> perms) {
        this.permissions = perms;
    }

}
