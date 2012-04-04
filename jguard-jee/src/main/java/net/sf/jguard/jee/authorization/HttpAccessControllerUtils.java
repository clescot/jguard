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
package net.sf.jguard.jee.authorization;

import net.sf.jguard.core.authentication.LoginContextWrapperImpl;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.AccessControlException;
import java.security.Permission;
import java.security.PrivilegedActionException;

/**
 * grab the {@link net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl} tied with the current {@link HttpSession}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpAccessControllerUtils {

    static public final Logger logger = LoggerFactory.getLogger(HttpAccessControllerUtils.class);
    private AccessControllerWrapperImpl accessControlWrapper;

    @Inject
    public HttpAccessControllerUtils(AccessControllerWrapperImpl accessControlWrapper) {

        this.accessControlWrapper = accessControlWrapper;
    }

    /**
     * checks if the {@link Subject} bound to the {@link HttpSession} has got the {@link Permission}.
     *
     * @param session
     * @param p
     * @throws AccessControlException
     * @throws PrivilegedActionException
     */
    public void checkPermission(HttpSession session, Permission p) throws AccessControlException, PrivilegedActionException {
        if (session == null) {
            throw new AccessControlException(" user is not yet authenticated ", p);
        }
        LoginContextWrapperImpl authNutils = (LoginContextWrapperImpl) session.getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
        if (authNutils != null) {
            Subject subject = authNutils.getSubject();
            if (subject == null) {
                throw new AccessControlException(" user is not yet authenticated ", p);
            }
            accessControlWrapper.checkPermission(subject, p);
        } else {
            session.removeAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
            throw new AccessControlException(" user is not yet authenticated ", p);
        }


    }

    /**
     * check if the user has got the permission and return the result as a boolean.
     * it does not throw any PrivilegedActionException or AccessControlException.
     *
     * @param request
     * @param p
     * @return
     */
    public boolean hasPermission(HttpServletRequest request, Permission p) {
        boolean result = true;
        try {
            checkPermission(request.getSession(true), p);
        } catch (AccessControlException ace) {
            logger.debug(ace.getMessage());
            result = false;
        } catch (PrivilegedActionException pae) {
            logger.debug(pae.getMessage());
            result = false;
        }

        return result;
    }

}
