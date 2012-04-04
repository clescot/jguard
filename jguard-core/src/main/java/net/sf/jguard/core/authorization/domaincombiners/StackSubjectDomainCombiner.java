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
package net.sf.jguard.core.authorization.domaincombiners;

import javax.security.auth.Subject;
import java.security.CodeSource;
import java.security.DomainCombiner;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 */
 class StackSubjectDomainCombiner implements DomainCombiner {
    private Subject subject;

    public StackSubjectDomainCombiner(Subject subj) {
        this.subject = subj;
    }

    /**
     * creates a new array of <code>ProtectionDomain</code>s
     * adds on the top of the currentDomains a new ProtectionDomain with null CodeSource,
     * a null classloader, empty permissions collection and the subject principals.<br>
     * assignedDomains is not combined.
     *
     * @param currentDomains  ProtectionDomain[]
     * @param assignedDomains ProtectionDomain[]
     */
    public ProtectionDomain[] combine(ProtectionDomain[] currentDomains,
                                      ProtectionDomain[] assignedDomains) {
        ProtectionDomain[] combinedPd = new ProtectionDomain[currentDomains.length + 1];
        System.arraycopy(currentDomains, 0, combinedPd, 0, currentDomains.length);
        CodeSource cs = new CodeSource(null, (Certificate[]) null);
        combinedPd[currentDomains.length] = new ProtectionDomain(cs, null, null,
                subject.getPrincipals().toArray(new Principal[subject.getPrincipals().size()]));
        return combinedPd;
    }

}
