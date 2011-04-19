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
package net.sf.jguard.core.provisioning;

import net.sf.jguard.core.authentication.exception.AuthenticationException;

import java.util.HashSet;
import java.util.Set;

/**
 * Exception raised during Registration.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net ">Charles Gay</a>
 */
public class RegistrationException extends AuthenticationException {

    private static final long serialVersionUID = -51540986121856569L;
    private Set missingPublicCredential = null;
    private Set missingPrivateCredential = null;

    public RegistrationException() {
        super();
        missingPrivateCredential = new HashSet();
        missingPublicCredential = new HashSet();
    }

    public RegistrationException(String msg) {
        super(msg);
        missingPrivateCredential = new HashSet();
        missingPublicCredential = new HashSet();
    }

    public RegistrationException(AuthenticationException e) {
        super(e);
    }

    public RegistrationException(String msg, Set missingPublicCred, Set missingPrivateCred) {
        super(msg);
        if (missingPrivateCred == null) {
            missingPrivateCred = new HashSet();
        }
        if (missingPublicCred == null) {
            missingPublicCred = new HashSet();
        }

        missingPublicCredential = missingPublicCred;
        missingPrivateCredential = missingPrivateCred;

    }


    public Set getMissingPrivateCredential() {
        return missingPrivateCredential;
    }

    public Set getMissingPublicCredential() {
        return missingPublicCredential;
    }
}
