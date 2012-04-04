/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2011  Charles Lescot
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * jGuard project home page:
 * http://sourceforge.net/projects/jguard/
 */

package net.sf.jguard.ext.log.logback;

import ch.qos.logback.core.pattern.DynamicConverter;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.util.SubjectUtils;

import javax.security.auth.Subject;
import java.security.AccessController;

/**
 * grab the current Subject and return the identity credential value, for the logback layout.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class JGuardCredentialConverter extends DynamicConverter {
    public static final String UNAUTHENTICATED = "UNAUTHENTICATED";
    public static final String NO_IDENTITY_CREDENTIAL = "NO IDENTITY CREDENTIAL";

    @Override
    public String convert(Object event) {
        String identityCredentialValue = UNAUTHENTICATED;
        Subject subject = Subject.getSubject(AccessController.getContext());
        String firstOption = getFirstOption();
        if (firstOption == null) {
            throw new IllegalArgumentException("firstOption is null. you must specify with this pattern the name of the jGuardCredential to return %jgc{chosenJguardCredentialName}");
        }
        if (null != subject) {
            JGuardCredential jGuardCredential = SubjectUtils.getIdentityCredentialValue(subject, firstOption);
            if (null != jGuardCredential && jGuardCredential.getValue() != null) {
                identityCredentialValue = (String) jGuardCredential.getValue();
            } else {
                identityCredentialValue = NO_IDENTITY_CREDENTIAL;
            }
        }
        return identityCredentialValue;
    }
}
