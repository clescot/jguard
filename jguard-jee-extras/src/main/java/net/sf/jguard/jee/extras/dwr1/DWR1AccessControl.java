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
package net.sf.jguard.jee.extras.dwr1;

import com.google.inject.Injector;
import net.sf.jguard.jee.authorization.HttpAccessControllerUtils;
import uk.ltd.getahead.dwr.AccessControl;
import uk.ltd.getahead.dwr.Creator;
import uk.ltd.getahead.dwr.impl.DefaultAccessControl;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.security.AccessControlException;
import java.security.Permission;
import java.security.PrivilegedActionException;
import java.util.logging.Logger;

/**
 * link DWR with jguard to unify access control in jguard.
 * this implementation works in DWR 1.x.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class DWR1AccessControl extends DefaultAccessControl implements AccessControl {
    private static final Logger logger = Logger.getLogger(DWR1AccessControl.class.getName());
    private HttpAccessControllerUtils httpAccessControllerUtils;
    private Injector injector;


    public String getReasonToNotDisplay(HttpServletRequest req,
                                        Creator creator, String className, Method method) {
        if (injector == null) {
            injector = (Injector) req.getSession(true).getServletContext().getAttribute(Injector.class.getName());
            this.httpAccessControllerUtils = injector.getInstance(HttpAccessControllerUtils.class);
        }
        StringBuffer actions = new StringBuffer();
        actions.append(creator.getClass().getName());
        actions.append(",");
        actions.append(creator.getType().getName());
        actions.append(",");
        actions.append(method.getName());
        Permission p = new DWR1Permission("dummy name created by DWR1AccessControl to check access  ", actions.toString());

        try {
            httpAccessControllerUtils.checkPermission(req.getSession(true), p);
        } catch (AccessControlException e) {
            logger.fine(e.getMessage());
            return e.getMessage();
        } catch (PrivilegedActionException e) {
            logger.fine(e.getMessage());
            return e.getMessage();
        }
        return null;
    }

    public String getReasonToNotExecute(HttpServletRequest req,
                                        Creator creator, String className, Method method) {

        return getReasonToNotDisplay(req, creator, className, method);
        //TODO make a distinction between permission at compile time and at execution
    }


    public void addRoleRestriction(String scriptName, String methodName, String role) {
        super.addRoleRestriction(scriptName, methodName, role);
    }

    public void addIncludeRule(String scriptName, String methodName) {
        super.addIncludeRule(scriptName, methodName);
    }

    public void addExcludeRule(String scriptName, String methodName) {
        super.addExcludeRule(scriptName, methodName);
    }
}
