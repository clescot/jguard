/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name:  $
http://sourceforge.net/projects/jguard

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
http://sourceforge.net/projects/jguard

*/
package net.sf.jguard.core.authorization.permissions;

import java.security.Permission;

/**
 * Permission granting special operation on the current {@link net.sf.jguard.core.authorization.policy.JGuardPolicy}
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public final class JGuardPolicyPermission extends Permission {

    private static final long serialVersionUID = -5897771811289873870L;
    private String name = null;
    private static final String ADD_ALWAYS_GRANTED_PERMISSION = "ADD_ALWAYS_GRANTED_PERMISSION";

    public JGuardPolicyPermission(String name) {
        super(name);
        if (ADD_ALWAYS_GRANTED_PERMISSION.equals(name)) {
            this.name = name;
        } else {
            throw new IllegalArgumentException(" name argument must be ADD_ALWAYS_GRANTED_PERMISSION ");
        }

    }

    public boolean equals(Object obj) {
        if (obj != null && JGuardPolicyPermission.class.equals(obj.getClass())) {
            JGuardPolicyPermission perm = (JGuardPolicyPermission) obj;
            if (name.equals(perm.getName())) {
                return true;
            }
        }
        return false;
    }

    public String getActions() {
        return null;
    }

    public int hashCode() {
        return name.hashCode();
    }

    public boolean implies(Permission permission) {
        return equals(permission);
    }

}
