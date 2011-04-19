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
package net.sf.jguard.core.authorization.workflow;

import java.security.Permission;

/**
 * Decorator used to decorate java.security.Permission subclasses
 * to add Dynamic Separation of Duty (DSOD) according to the
 * Role Based Access Control (RBAC) standard.
 * it controls when decorated permission implies the permission checked,
 * that the 'Workflow Checker' allows this permission.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class DSODDecorator extends Permission {

    private static final long serialVersionUID = 6660070267190082422L;
    private Permission permission = null;
    private WorkflowCheckerFactory wcf = null;

    public DSODDecorator(WorkflowCheckerFactory wcf, Permission p) {
        super(p.getName());
        this.permission = p;
        this.wcf = wcf;
    }

    public boolean equals(Object obj) {
        if (obj instanceof DSODDecorator) {
            DSODDecorator duration = (DSODDecorator) obj;
            if (this.permission.getName().equals(duration.getName())
                    && this.permission.getActions().equals(duration.getActions())) {
                return true;
            }
        }
        return false;
    }

    public String getActions() {
        return permission.getActions();
    }

    public int hashCode() {
        return this.permission.hashCode() + wcf.hashCode();
    }

    public boolean implies(Permission permission) {
        // TODO Auto-generated method stub
        return false;
    }

}
