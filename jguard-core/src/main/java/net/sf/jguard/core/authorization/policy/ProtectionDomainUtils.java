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
package net.sf.jguard.core.authorization.policy;

import net.sf.jguard.core.authorization.permissions.UserPrincipal;

import javax.security.auth.Subject;
import java.lang.reflect.Array;
import java.net.URL;
import java.security.CodeSource;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility class related to {@link ProtectionDomain}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public final class ProtectionDomainUtils {


    private ProtectionDomainUtils() {

    }

    public static UserPrincipal getUserPrincipal(ProtectionDomain protectionDomain) {
        Set<Principal> ppals = new HashSet<Principal>(Arrays.asList(protectionDomain.getPrincipals()));
        UserPrincipal userPrincipal = null;


        //TODO CGA add SSODPermissions (java.security.Permissions) decorator
        //to support Static Separation Of Duty (an RBAC feature)
        // it will handle SSOD purpose in a static way with
        // any AuthorizationManager implementation

        // Find the UserPrincipal to evaluate definitions

        for (Object ppal1 : ppals) {
            Principal ppal = (Principal) ppal1;
            if (ppal instanceof UserPrincipal) {
                userPrincipal = (UserPrincipal) ppal;
                break;
            }
        }
        return userPrincipal;


    }


    public static Subject getSubject(ProtectionDomain protectionDomain) {
        UserPrincipal userPrincipal = getUserPrincipal(protectionDomain);
        if (userPrincipal != null) {
            return userPrincipal.getSubject();
        } else {
            return null;
        }
    }

    /**
     * return a {@link ProtectionDomain} containing only the principal and a fake {@link CodeSource} and no permissions.
     * it is used to only containing the principal, which will be bound to permissions by the current {@link Policy}.
     *
     * @param principal
     * @return an empty ProtectionDomain with the principal
     */
    public static ProtectionDomain getEmptyProtectionDomain(Principal principal) {
        URL url = null;
        Certificate[] certs = null;
        CodeSource cs = new CodeSource(url, certs);
        Principal[] array = (Principal[]) Array.newInstance(principal.getClass(), 1);
        Array.set(array, 0, principal);
        return new ProtectionDomain(cs, null, Thread.currentThread().getContextClassLoader(), array);
    }

    /**
     * return a {@link ProtectionDomain} containing a collection of principals, no permissions and a fake {@link CodeSource}.
     * Principals will be bound further to permissions by the current Policy.
     *
     * @param principals
     * @return an empty ProtectionDomain with the principals
     */
    public static ProtectionDomain getEmptyProtectionDomain(Collection<Principal> principals) {
        Principal[] ppals = principals.toArray(new Principal[principals.size()]);
        URL url = null;
        Certificate[] certs = null;
        CodeSource cs = new CodeSource(url, certs);
        return new ProtectionDomain(cs, null, Thread.currentThread().getContextClassLoader(), ppals);
    }

}
