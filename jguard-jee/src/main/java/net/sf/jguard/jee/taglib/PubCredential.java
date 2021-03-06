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
package net.sf.jguard.jee.taglib;

import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.util.Set;

/**
 * display the Public Credential of the Subject.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class PubCredential extends JGuardTagCredential {
    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(PubCredential.class);
    /**
     * serial version id.
     */
    private static final long serialVersionUID = 3257570611415888950L;


    protected Set<JGuardCredential> getCredentials(Subject subject) {
        return subject.getPublicCredentials(JGuardCredential.class);
    }

    protected boolean isPrivate() {
        return false;
    }

    protected String getTagName() {
        return "PubCredential";
    }

}
