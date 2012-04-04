/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name:  $
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
package net.sf.jguard.core.authorization.permissions;

import java.security.Permission;
import java.util.Iterator;

/**
 * JGPermissionCollection with a <strong>negative</strong> mechanism. 
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 * @author <a href="mailto:diabolo512@users.sourceforge.net ">Charles Lescot</a>
 * @see net.sf.jguard.core.authorization.permissions.JGPermissionCollection
 */
public class JGNegativePermissionCollection extends JGPermissionCollection{

	
	private static final long serialVersionUID = -1791631206621754946L;

	
	public JGNegativePermissionCollection(){
		super();
	}
	
	/** verify if this permission implies the other permission.
	 * @see java.security.PermissionCollection#implies(java.security.Permission)
	 */
	public boolean implies(Permission permission) {
        Iterator it = permissions.iterator();
		Permission p;

        while(it.hasNext()){
			p = (Permission) it.next();
			if (p.implies(permission)) {
				return false;
			}
		}
		return true;
	}
	
}
