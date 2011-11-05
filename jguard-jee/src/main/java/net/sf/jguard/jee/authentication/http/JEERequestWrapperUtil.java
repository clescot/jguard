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
package net.sf.jguard.jee.authentication.http;

import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.principals.RolePrincipal;
import net.sf.jguard.core.principals.UserPrincipal;
import net.sf.jguard.core.util.SubjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequestWrapper;
import java.security.Principal;
import java.util.Set;

/**
 * utility class for JEE wrappers like {@link HttpServletRequestWrapper} or
 * JGuardPortletRequestWrapper.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class JEERequestWrapperUtil {

    private static Logger logger = LoggerFactory.getLogger(JEERequestWrapperUtil.class);

    /**
     * return the 'identity' credential value converted to a String.
     * note that <strong>only one</strong> credential must be an identity credential.
     *
     * @param loginContextWrapper
     * @param authManager
     * @return
     */
    public static String getRemoteUser(LoginContextWrapper loginContextWrapper, AuthenticationManager authManager) {
        String remoteUser = null;
        if(loginContextWrapper==null){
            return remoteUser;
        }

        if(authManager==null){
            throw new IllegalArgumentException("authenticationManager is null");
        }
        Subject subject = loginContextWrapper.getSubject();
        if (subject == null) {
            return remoteUser;
        } else {

            JGuardCredential identityCred = SubjectUtils.getIdentityCredential(subject, authManager);
            if (identityCred == null) {
                return null;
            }
            Object value = identityCred.getValue();
            if (value != null) {
                remoteUser = value.toString();
            }

        }
        return remoteUser;
    }

    /**
     *
     * @param applicationName
     * @param role
     * @param loginContextWrapper
     * @return
     */
    public static boolean isUserInRole(String applicationName, String role, LoginContextWrapper loginContextWrapper) {
        if (applicationName == null || "".equals(applicationName)) {
           throw new IllegalArgumentException("applicationName is null");
        }
        if (role == null || "".equals(role)) {
           throw new IllegalArgumentException("role is null");
        }

        if (loginContextWrapper == null) {
           throw new IllegalArgumentException("loginContextWrapper is null");
        }
        String composedRoleName = new StringBuffer(applicationName).append('#').append(role).toString();
        Subject subject = loginContextWrapper.getSubject();
        if(subject == null){
            throw new IllegalArgumentException("subject in loginContextWrapper is null");
        }
        Set principals = subject.getPrincipals(RolePrincipal.class);
        for (Object principal1 : principals) {
            Principal principal = (Principal) principal1;
            if (composedRoleName.equals(principal.getName())) {
                return true;
            }
        }
        return false;
    }

    /**
     * return a {@link UserPrincipal} which embeds a {@link Subject}.
     *
     * @param loginContextWrapper
     * @return
     */
    public static Principal getUserPrincipal(LoginContextWrapper loginContextWrapper) {
        if (loginContextWrapper == null) {
            throw new IllegalArgumentException("loginContextWrapper is null");
        }
        Subject subject = loginContextWrapper.getSubject();
        return new UserPrincipal(subject);
    }

}
