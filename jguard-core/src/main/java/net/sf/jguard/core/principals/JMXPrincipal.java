/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name:  $
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
package net.sf.jguard.core.principals;

/**
 * This principal is added in JMX connection to keep a reference of the objectID used in Policy.
 *
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 * @see net.sf.jguard.core.authorization.policy.MultipleAppPolicy#implies(java.security.ProtectionDomain domain, java.security.Permission)
 */
public class JMXPrincipal implements BasePrincipal, Cloneable {

    private static final long serialVersionUID = -7340042412040356992L;

    private final String applicationName;
    private final Object objectID;

    public JMXPrincipal(String applicationName, Object objectID) {
        this.applicationName = applicationName;
        this.objectID = objectID;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        return new JMXPrincipal(this.applicationName, this.objectID);
    }

    public int compareTo(Object arg) {
        if (this.equals(arg)) {
            return 0;
        }
        if (arg instanceof JMXPrincipal) {
            return applicationName.compareTo(((JMXPrincipal) arg).getApplicationName());
        }
        return 1;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        JMXPrincipal that = (JMXPrincipal) o;

        if (!applicationName.equals(that.applicationName)) return false;
        return objectID.equals(that.objectID);

    }

    @Override
    public int hashCode() {
        int result = applicationName.hashCode();
        result = 31 * result + objectID.hashCode();
        return result;
    }

    public String getName() {
        return applicationName + objectID.getClass().getName();
    }

    String getApplicationName() {
        return applicationName;
    }


    public Object getObjectID() {
        return objectID;
    }

}
