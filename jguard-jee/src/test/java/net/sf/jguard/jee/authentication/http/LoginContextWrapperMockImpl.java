/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name: v080beta1 $
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
package net.sf.jguard.jee.authentication.http;

import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.LoginContextWrapperImpl;

import javax.inject.Inject;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;

public class LoginContextWrapperMockImpl extends LoginContextWrapperImpl {
    private Subject subject = null;

    @Inject
    public LoginContextWrapperMockImpl(@ApplicationName String applicationName,
                                       Configuration configuration) {
        super(applicationName, configuration);
    }

    public Subject getSubject() {
        return subject;
    }

    public void setSubject(Subject subj) {
        subject = subj;
    }
}
