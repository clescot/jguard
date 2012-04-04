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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.DomainCombiner;
import java.security.ProtectionDomain;

/**
 * only handle assigned protectionDomains, and avoid protectionDomains from the system.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
class RestrictDomainCombiner implements DomainCombiner {

    private static final Logger logger = LoggerFactory.getLogger(RestrictDomainCombiner.class.getName());

    /**
     * return only the assigned domains.
     *
     * @param currentDomains  from the current execution Thread (since the last AccessController.doPrivileged
     *                        if this call has been made, or only the current otherwise)
     * @param assignedDomains array of inherited ProtectionDomains
     * @return combined ProtectionDomain array
     * @see ProtectionDomain
     */
    public ProtectionDomain[] combine(ProtectionDomain[] currentDomains,
                                      ProtectionDomain[] assignedDomains) {
        return assignedDomains;
	}

}
