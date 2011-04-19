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
package net.sf.jguard.jsf.permissions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.BasicPermission;
import java.security.Permission;
import java.util.regex.Pattern;

/**
 * {@link java.security.Permission} subclass dedicated to describe Java Server Faces resources.
 * it represents access to JSF views.
 * Note that name is treated as a  {@link java.util.regex.Pattern}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public final class JSFPermission extends BasicPermission {

    private static final long serialVersionUID = -868442531347309291L;

    private static final Logger logger = LoggerFactory.getLogger(JSFPermission.class.getName());
    private Pattern pattern;


    /**
     * @param name view Id
     */
    public JSFPermission(String name) {
        super(name);
        if ("*".equals(name)) {
            name = ".*";
        }
        pattern = Pattern.compile(name);
    }

    public boolean equals(Object obj) {
        if (obj != null && obj instanceof JSFPermission) {
            JSFPermission jsfp = (JSFPermission) obj;
            return getName().equals(jsfp.getName());
        }
        return false;
    }

    public String getActions() {
        return "";
    }

    public int hashCode() {
        return getName().hashCode();
    }

    public boolean implies(Permission permission) {
        if (!(permission instanceof JSFPermission)) {
            if (logger.isDebugEnabled()) {
                logger.debug(" permission is not a JSFPermission. type = " + permission.getClass().getName());
            }
            return false;
        } else {
            JSFPermission jsfPermission = (JSFPermission) permission;
            return pattern.matcher(jsfPermission.getName()).matches();
        }
    }

}
