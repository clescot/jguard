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
package net.sf.jguard.core.authorization.workflow;

import java.security.Permission;
import java.util.Date;

/**
 * decorate java.security.Permission subclasses by defining a duration
 * for their validity.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class DurationDecorator extends Permission {

    private static final long serialVersionUID = 3085444057980849140L;
    private Permission permission;
    private Date begin;
    private Date end;

    /**
     * @param p     permission to decorate
     * @param start begin date of the duration: can be <i>null</i> if there is no begin
     * @param stop  end date of the duration : can be <i>null</i> if there is no end
     */
    public DurationDecorator(Permission p, Date start, Date stop) {
        super(p.getName());
        this.permission = p;
        if (start != null) {
            this.begin = new Date(start.getTime());
        }
        if (stop != null) {
            this.end = new Date(stop.getTime());
        }
    }


    public String getActions() {
        return permission.getActions();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        DurationDecorator that = (DurationDecorator) o;

        if (begin != null ? !begin.equals(that.begin) : that.begin != null) {
            return false;
        }
        if (end != null ? !end.equals(that.end) : that.end != null) {
            return false;
        }
        return permission.equals(that.permission);

    }

    @Override
    public int hashCode() {
        int result = permission.hashCode();
        result = 31 * result + (begin != null ? begin.hashCode() : 0);
        result = 31 * result + (end != null ? end.hashCode() : 0);
        return result;
    }

    public boolean implies(Permission permission) {
        if (!(permission instanceof DurationDecorator)) {
            return false;
        }
        DurationDecorator decorator = (DurationDecorator) permission;

        Date now = new Date();
        if (begin != null && now.before(begin)) {
            return false;
        }
        if (end != null && now.after(end)) {
            return false;
        }
        //duration check succeed,
        //so we check in a classic way the permission
        return this.permission.implies(decorator.permission);
    }

}
