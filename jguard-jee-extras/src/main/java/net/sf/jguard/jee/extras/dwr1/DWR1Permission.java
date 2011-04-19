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
package net.sf.jguard.jee.extras.dwr1;

import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;

import java.security.BasicPermission;
import java.security.Permission;

/**
 * represents the permission to instantiate some methods of beans from javascript
 * via <a href="http://dwr.dev.java.net/">DWR</a>.
 * this implementation works in DWR 1.x.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public final class DWR1Permission extends BasicPermission {

    private static final long serialVersionUID = -5380977262062636050L;
    private String name = null;
    private String creatorClassName = null;
    private String className = null;
    private String methodName = null;
    private String actions = null;

    /**
     * this permission requires a 'name' and an 'actions' string.
     * this actions string must contains 3 actions divided by ','.
     * first action is :'creatorClassName' : the class name of the creator.
     * second action is 'className':the Class which will be instantiated by the Creator.
     * third action is 'methodName': the Class which will be instantiated by the Creator.
     * multiple method can have the same name, but it seems that DWR make no distinction between them.
     * the method used when multiple methods ahve got thze same name is not clear (to me).
     *
     * @param name
     * @param actions
     */
    public DWR1Permission(String name, String actions) {
        //TODO make distinction between permission at compile time and permission at execution
        super(name);
        this.name = name;
        this.actions = actions;
        if (name == null) {
            throw new IllegalArgumentException(" 'name' must not be null ");
        }
        String[] actionsArray = actions.split(",");
        if (actionsArray.length != 3) {
            throw new IllegalArgumentException(" DWR1Permission must have 3 actions : creatorClassName,className and methodName ");
        }
        creatorClassName = actionsArray[0];
        className = actionsArray[1];
        methodName = actionsArray[2];
        if (creatorClassName == null || className == null || methodName == null) {
            throw new IllegalArgumentException(" one or more of these arguments are 'null' : \n name=" + name + "creatorClassName =" + creatorClassName + " className= " + className);
        }
    }

    public int hashCode() {
        return name.hashCode() + creatorClassName.hashCode() + className.hashCode() + methodName.hashCode();
    }

    public boolean equals(Object object) {
        if (!(object instanceof DWR1Permission)) {
            return false;
        } else {
            DWR1Permission dwrPerm = (DWR1Permission) object;
            return !(name.equals(dwrPerm.getName()) || !creatorClassName.equals(dwrPerm.getCreatorClassName()) || !className.equals(dwrPerm.getClassName()) || !methodName.equals(dwrPerm.getMethodName()));
        }
    }


    public boolean implies(Permission p) {
        if (!(p instanceof DWR1Permission)) {
            return false;
        } else {
            DWR1Permission dwrPerm = (DWR1Permission) p;
            return !(!creatorClassName.equals(dwrPerm.getCreatorClassName()) || !className.equals(dwrPerm.getClassName()) || !methodName.equals(dwrPerm.getMethodName()));
        }

    }

    public String getClassName() {
        return className;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getCreatorClassName() {
        return creatorClassName;
    }

    public String toString() {
        StringBuffer buffer = new StringBuffer();
        buffer.append("name=");
        buffer.append(name);
        buffer.append(",");
        buffer.append("creatorClassName=");
        buffer.append(creatorClassName);
        buffer.append(",");
        buffer.append("className=");
        buffer.append(className);
        buffer.append(",");
        buffer.append("methodName=");
        buffer.append(methodName);
        return buffer.toString();

    }

    /**
     * return an enmpy JGPermissionCollection.
     *
     * @return empty JGPermissionCollection
     */
    public java.security.PermissionCollection newPermissionCollection() {
        return new JGPositivePermissionCollection();
    }

    public String getActions() {
		return actions;
	}
}
