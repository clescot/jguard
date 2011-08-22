package net.sf.jguard.ext.authorization.manager;

import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.NegativePermissions;
import net.sf.jguard.core.PermissionResolutionCaching;
import net.sf.jguard.core.authorization.manager.AuthorizationManagerException;

import javax.inject.Inject;
import java.security.Permission;
import java.security.Principal;
import java.util.List;
import java.util.Map;

/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.

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
public class JPAAuthorizationManager extends AbstractAuthorizationManager{
    /**
     * initialize AuthorizationManager implementation.
     * @param applicationName
     * @param negativePermissions
     * @param permissionResolutionCaching
     */
    @Inject
    public JPAAuthorizationManager(@ApplicationName String applicationName,
                                   @NegativePermissions boolean negativePermissions,
                                   @PermissionResolutionCaching boolean permissionResolutionCaching) {
        super(applicationName,negativePermissions,permissionResolutionCaching);
        checkInitialState();
    }

    @Override
    public void refresh() {

    }

    public List getInitParameters() {
        return null;
    }

    public void createPermission(Permission url) throws AuthorizationManagerException {

    }

    public void updatePermission(String oldPermissionName, Permission updatedPermission) throws AuthorizationManagerException {

    }

    public void deletePermission(String permissionName) throws AuthorizationManagerException {

    }

    public void createPrincipal(Principal principal) throws AuthorizationManagerException {

    }

    public void updatePrincipal(String oldPrincipalName, Principal principal) throws AuthorizationManagerException {

    }

    public void deletePrincipal(Principal principal) throws AuthorizationManagerException {

    }

    public boolean isEmpty() {
        return false;
    }
}
