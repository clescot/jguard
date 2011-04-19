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
package net.sf.jguard.core.authorization.policy;

import com.google.inject.Inject;

import javax.security.auth.Subject;
import java.security.*;
import java.util.Set;


/**
 * {@link AccessController} clone used to check permission against an isolated Policy
 * not tight to the system Policy.
 * this implementation permits to do some checks when no java SecurityManager is in place.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @see java.security.AccessController
 * @since 1.0
 */
public class LocalAccessController {

    private Policy policy;

    @Inject
    public LocalAccessController(Policy policy) {
        this.policy = policy;
    }


    /**
     * controls that the provided Subject has got the permission requested
     * against the Policy.
     *
     * @param permission to check
     * @throws AccessControlException when access is denied
     */
    public void checkPermission(Permission permission) throws AccessControlException {
        if (permission == null) {
            throw new IllegalArgumentException(" permission provided is null ");
        }

        //we take a snapshot of the security context
        AccessControlContext acc = AccessController.getContext();

        if (acc == null) {
            //system code is always allowed
            return;
        }

        //we grab the Subject related to the accessControlContext
        Subject subject = Subject.getSubject(acc);
        if (subject == null) {
            //like this class is used in 'local' mode,
            //the security is not tight with the jvm security
            //we don't make restrictions when this code can be
            //avoided easily
            // to have a more deep security, use the 'jvm' mode
            return;
        }


        Set<Principal> principals = subject.getPrincipals();
        //get a ProtectionDomain only owning Principals, no permissions, and a fake CodeSource
        ProtectionDomain domain = ProtectionDomainUtils.getEmptyProtectionDomain(principals);
        //get permissions bound to principals owned by the Subject
        PermissionCollection permColl = policy.getPermissions(domain);
        if (!permColl.implies(permission)) {
            StringBuilder sb = new StringBuilder(" permission ");
            throw new AccessControlException(sb.append(permission.toString()).append(" is not granted ").toString(), permission);
        }
    }

}
