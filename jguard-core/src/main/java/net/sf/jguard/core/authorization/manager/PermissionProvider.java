/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name$
http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles Lescot

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

import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.ProtectionDomain;


/**
 * PermissionProvider interface is base interface for AuthorizationManager.
 * This interface is introduced to make coupling of JGuardPolicy to other
 * classes in the framework as small as possible.  
 * 
 * @author <a href="mailto:zelfdoen@users.sourceforge.net">Theo Niemeijer</a>
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public interface PermissionProvider {

    /**
     * Get permission collection.
     *
     * @param pDomain - set value for principals
     *
     * @return permission collection value
     */
    PermissionCollection getPermissions(ProtectionDomain pDomain);

    /**
     * refresh principals and permissions data.
     */
    void refresh();
    
    /**
     * add some permissions always granted by this Policy, like permission used to
     * <i>logoff</i> in webapp, or permissions used to reached the <i>AccessDenied</i> page.
     * @param permissions permissions always granted by this Policy
     */
    void addAlwaysGrantedPermissions(Permissions permissions);
         
}
