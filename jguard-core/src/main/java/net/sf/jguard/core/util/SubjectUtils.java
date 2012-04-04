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
package net.sf.jguard.core.util;

import net.sf.jguard.core.authentication.callbacks.GuestCallbacksProvider;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.principals.Organization;
import net.sf.jguard.core.principals.PrincipalUtils;
import net.sf.jguard.core.principals.RolePrincipal;
import net.sf.jguard.core.principals.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * utility class to query against subject credentials.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
public final class SubjectUtils {


    private static final Logger logger = LoggerFactory.getLogger(SubjectUtils.class.getName());
    private static final String USER_PRINCIPAL = "userPrincipal";
    public static final String GUEST_SUBJECT = "guestSubject";


    private SubjectUtils() {

    }


    /**
     * return credential values from the specified credential set
     * which are mapped to the specified credentialId.
     *
     * @param subject
     * @param publicVisibility <i>true</i> for publicCredentials, <i>false</i> for
     *                         private credentials.
     * @param credentialId
     * @return Collection of Object credential values
     */
    private static Set getCredentialValues(Subject subject, boolean publicVisibility, String credentialId) {
        Set valuesFound = new HashSet();
        Set<JGuardCredential> credentials;
        if (publicVisibility) {
            credentials = subject.getPublicCredentials(JGuardCredential.class);
        } else {
            try {
                credentials = subject.getPrivateCredentials(JGuardCredential.class);
            } catch (SecurityException sex) {
                logger.debug(" you don't have the permission to grab private credentials ");
                return valuesFound;
            }
        }
        for (JGuardCredential credential : credentials) {
            //we skip non JGuardCredentials
            if (!(credential instanceof JGuardCredential)) {
                continue;
            }
            JGuardCredential cred = credential;
            if (cred.getName().equals(credentialId)) {
                valuesFound.add(cred.getValue());
            }
        }

        return valuesFound;
    }

    public static Organization getOrganization(Subject subject) {
        Set<Organization> organizationSet = subject.getPrincipals(Organization.class);
        if (organizationSet.size() > 1) {
            throw new IllegalStateException(" a Subject object must contains only one organization in the principal set . ");
        } else if (organizationSet.size() == 0) {
            throw new IllegalStateException(" if no organization is set in the principal set of the subject, the default 'system' organization is used  ");
        }
        return organizationSet.iterator().next();
    }

    /**
     * return credential value from the specified credential set
     * This function assume that credential have only one value
     * return empty string if it is not found
     *
     * @param subject
     * @param publicVisibility <i>true</i> for publicCredentials, <i>false</i> for
     *                         private credentials.
     * @param credentialId
     * @return credential value as string
     */
    public static String getCredentialValueAsString(Subject subject, boolean publicVisibility, String credentialId) {
        String valueFound = "";
        Set<JGuardCredential> credentials;
        if (publicVisibility) {
            credentials = subject.getPublicCredentials(JGuardCredential.class);
        } else {
            try {
                credentials = subject.getPrivateCredentials(JGuardCredential.class);
            } catch (SecurityException sex) {
                logger.debug(" you don't have the permission to grab private credentials ");
                return valueFound;
            }
        }
        for (JGuardCredential credential : credentials) {
            if (credential.getName().equals(credentialId)) {
                valueFound = credential.getValue().toString();
                break;
            }
        }

        return valueFound;
    }

    /**
     * Set credential's value, this method assume that credential have only one value
     * If credentialId exists then the value is replaced, else the credential is created
     *
     * @param subject
     * @param publicVisibility <i>true</i> for publicCredentials, <i>false</i> for
     *                         private credentials.
     * @param credentialId
     * @param credentialValue
     * @param isIdentity       <i>true</i> for identity credential, <i>false</i> otherwise
     */
    public static void setCredentialValue(Subject subject, boolean publicVisibility, String credentialId, Object credentialValue, boolean isIdentity) {
        Set credentials;
        boolean credFound = false;
        if (publicVisibility) {
            credentials = subject.getPublicCredentials();
        } else {
            try {
                credentials = subject.getPrivateCredentials();
            } catch (SecurityException sex) {
                logger.debug(" you don't have the permission to grab private credentials ");
                return;
            }
        }
        Iterator it = credentials.iterator();
        JGuardCredential jCred = null;
        JGuardCredential newJCred = null;
        while (it.hasNext()) {
            Object credential = it.next();
            if (!(credential instanceof JGuardCredential)) {
                continue;
            } else {
                jCred = (JGuardCredential) credential;
            }

            if (jCred.getName().equals(credentialId)) {
                newJCred = new JGuardCredential(credentialId, credentialValue);
                credFound = true;
                break;
            }
        }
        if (!credFound) {
            newJCred = new JGuardCredential(credentialId, credentialValue);
        }
        credentials.remove(jCred);
        credentials.add(newJCred);

    }


    /**
     * return a copy of the {link {@link JGuardCredential} identifying uniquely the user.
     *
     * @param subject
     * @param authenticationManager
     * @return
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    public static JGuardCredential getIdentityCredential(Subject subject, AuthenticationManager authenticationManager) {
        String userCredentialId = authenticationManager.getCredentialId();
        if (subject == null) {
            throw new IllegalArgumentException("'subject' parameter is null");
        }

        return getIdentityCredentialValue(subject, userCredentialId);
    }

    /**
     * return as a string the identity crednetial, part of the public credential set.
     *
     * @param subject
     * @param userCredentialId
     * @return
     */
    public static JGuardCredential getIdentityCredentialValue(Subject subject, String userCredentialId) {
        Set<JGuardCredential> publicCredentials = subject.getPublicCredentials(JGuardCredential.class);
        Set<JGuardCredential> credentialsFound = new HashSet<JGuardCredential>();
        for (JGuardCredential credential : publicCredentials) {
            if (userCredentialId.equals(credential.getName())) {
                credentialsFound.add(credential);
            }
        }

        if (credentialsFound.isEmpty()) {
            return null;
        }
        if (credentialsFound.size() > 1) {
            throw new IllegalStateException(credentialsFound.size() + " values found. there must be only one value for identity credential.");
        }
        return credentialsFound.iterator().next();
    }


    public static Set getEnabledPrincipals(Set<Principal> userPrincipals) {
        Set<RolePrincipal> enabledPrincipals = new HashSet<RolePrincipal>();
        // Find the UserPrincipal to evaluate principal definition
        UserPrincipal userPrincipal = null;
        Iterator<Principal> userPrincipalsIt = userPrincipals.iterator();
        while (userPrincipalsIt.hasNext()) {
            Principal ppal = userPrincipalsIt.next();
            if (ppal instanceof UserPrincipal) {
                userPrincipal = (UserPrincipal) ppal;
                break;
            }
        }
        userPrincipalsIt = userPrincipals.iterator();
        //add all enabled Principals to set
        while (userPrincipalsIt.hasNext()) {
            Principal ppal = userPrincipalsIt.next();
            if (ppal instanceof RolePrincipal) {
                RolePrincipal tempUserPrincipal = (RolePrincipal) ppal;
                if (!USER_PRINCIPAL.equals(tempUserPrincipal.getLocalName()) && PrincipalUtils.evaluatePrincipal(tempUserPrincipal, userPrincipal)) {
                    enabledPrincipals.add(tempUserPrincipal);
                }
            }
        }

        return enabledPrincipals;
    }

    public static Subject getGuestSubject(AuthenticationManager authenticationManager){
        Subject guestSubject = new Subject();
        guestSubject.getPrivateCredentials().add(new JGuardCredential(authenticationManager.getCredentialId(),GuestCallbacksProvider.GUEST));
        guestSubject.getPrivateCredentials().add(new JGuardCredential(authenticationManager.getCredentialPassword(), GuestCallbacksProvider.GUEST));
        return guestSubject;
    }


}
