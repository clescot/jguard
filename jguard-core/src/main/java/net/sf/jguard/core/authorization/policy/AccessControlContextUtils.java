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
package net.sf.jguard.core.authorization.policy;

import net.sf.jguard.core.authorization.domaincombiners.RestrictDomainCombiner;
import net.sf.jguard.core.authorization.domaincombiners.StackSubjectDomainCombiner;
import net.sf.jguard.core.principals.RolePrincipal;

import javax.security.auth.Subject;
import java.security.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

/**
 * utility class for authorization work related to {@link AccessControlContext} and {@link ProtectionDomain}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 * @see java.security.AccessControlContext
 * @see java.security.ProtectionDomain
 */
public final class AccessControlContextUtils {
    private static final ProtectionDomain[] EMPTY_PROTECTION_DOMAIN = new ProtectionDomain[0];


    private AccessControlContextUtils() {

    }

    /**
     * return the convenient {@link AccessControlContext} corresponding to the principal.
     * the returned AccessControlContext is bound to a {@link RestrictDomainCombiner}.
     *
     * @param principal RolePrincipal used to restrict execution code rights
     * @return object embedding used to restrict permissions
     */
    public static AccessControlContext getRestrictedAccessControlContext(Principal principal) {
        ProtectionDomain pd = ProtectionDomainUtils.getEmptyProtectionDomain(principal);
        DomainCombiner restrictDomainCombiner = new RestrictDomainCombiner();
        AccessControlContext acc = new AccessControlContext(new ProtectionDomain[]{pd});
        return new AccessControlContext(acc, restrictDomainCombiner);
    }

    /**
     * gets an <code>AccessControlContext</code> containing a single <code>ProtectionDomain</code>
     * with an <code>null</code> <code>CodeSource</code>, an empty array of <code>Certificates</code>,
     * the current <code>Thread</code> <code>ClassLoader</code>, and the subject principals.
     *
     * @param subject
     * @return the generated AccessControlContext
     */
    public static AccessControlContext getSubjectOnlyAccessControlContext(Subject subject) {
        ProtectionDomain pd = new ProtectionDomain(new CodeSource(null, (Certificate[]) null), null, Thread.currentThread().getContextClassLoader(), subject.getPrincipals().toArray(new Principal[subject.getPrincipals().size()]));
        ProtectionDomain[] pds = new ProtectionDomain[1];
        pds[0] = pd;
        return new AccessControlContext(pds);
    }

    /**
     * build an {@link AccessControlContext} with one ProtectionDomain with principals from
     * provided subject, and a null CodeSource and Classloader.
     *
     * @param subject
     * @return
     */
    public static AccessControlContext getStackSubjectAccessControlContext(Subject subject) {
        ProtectionDomain[] arrayPd = EMPTY_PROTECTION_DOMAIN;
        AccessControlContext acc = new AccessControlContext(arrayPd);
        DomainCombiner dc = new StackSubjectDomainCombiner(subject);
        return new AccessControlContext(acc, dc);
    }

    /**
     * return the convenient {@link AccessControlContext} containing the collection of Principal
     * but no permissions and a fake [@link CodeSource}.
     * the current Policy will further bound permissions to these principals.
     *
     * @param principals RolePrincipal used to restrict execution code rights
     * @return object used to restrict permissions
     */
    public static AccessControlContext getAccessControlContext(Collection principals) {
        Iterator itPrincipals = principals.iterator();
        Collection protectionDomains = new ArrayList();
        while (itPrincipals.hasNext()) {
            RolePrincipal principal = (RolePrincipal) itPrincipals.next();
            protectionDomains.add(ProtectionDomainUtils.getEmptyProtectionDomain(principal));
        }
        return new AccessControlContext((ProtectionDomain[]) protectionDomains.toArray(new ProtectionDomain[protectionDomains.size()]));
    }

}
