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

package net.sf.jguard.core.principals;

import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class EntityTemplate implements Cloneable, Serializable {


    private static final Logger logger = LoggerFactory.getLogger(EntityTemplate.class.getName());


    EntityTemplate() {
        super();

    }


    /**
     * get credentials from set in a <b>non-destructive</b> way.
     *
     * @param credentialSetFromTemplate
     * @param credentialSetFromCandidate
     * @return new set containing credentials from credentialSetFromUser that are in credentialSetFromTemplate
     */
    static Set<JGuardCredential> getCredentials(Set<JGuardCredential> credentialSetFromTemplate, Set<JGuardCredential> credentialSetFromCandidate) {
        Set<JGuardCredential> creds = new HashSet<JGuardCredential>();

        for (JGuardCredential jcred : credentialSetFromTemplate) {
            for (JGuardCredential jcredFromUser : credentialSetFromCandidate) {
                //we are looking for the right credential id, but not the right value
                if (jcred.getName().equals(jcredFromUser.getName())) {
                    creds.add(jcred);
                    break;
                }
            }
        }

        return creds;
    }


    /**
     * remove unknown credentials <b>in a destructive way</b> in the Credential set  from the Candidate entity.
     *
     * @param credentialSetFromTemplate
     * @param credentialSetFromCandidate
     * @return credential Set not registered
     */
    static Set<JGuardCredential> filterCredentialSet(Set<JGuardCredential> credentialSetFromTemplate, Set<JGuardCredential> credentialSetFromCandidate) {
        Iterator itCredentialFromTemplate;
        //looking for credentials not registered in the SubjectTemplate reference
        Set<JGuardCredential> credentialsNotRegistered = new HashSet<JGuardCredential>();
        Iterator itCredentialFromUser = credentialSetFromCandidate.iterator();
        while (itCredentialFromUser.hasNext()) {
            JGuardCredential jcredFromUser = (JGuardCredential) itCredentialFromUser.next();
            itCredentialFromTemplate = credentialSetFromTemplate.iterator();
            boolean found = false;
            while (itCredentialFromTemplate.hasNext()) {
                JGuardCredential jcredFromTemplate = (JGuardCredential) itCredentialFromTemplate.next();
                if (jcredFromUser.getName().equals(jcredFromTemplate.getName())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                credentialsNotRegistered.add(jcredFromUser);
                //we remove from the credential set the
                // unknown credential
                itCredentialFromUser.remove();
            }
        }
        return credentialsNotRegistered;
    }


    /**
     * validate credentials from the User against credentials from the SubjectTemplate.
     * unknown credentials are filtered.
     *
     * @param credentialSetFromTemplate
     * @param credentialSetFromCandidate
     * @return missing credentials in the related user's credential set
     */
    static Set<JGuardCredential> validateCredentialSet(Set<JGuardCredential> credentialSetFromTemplate, Set credentialSetFromCandidate) {
        Iterator itCredentialFromTemplate = credentialSetFromTemplate.iterator();
        Set<JGuardCredential> missingCredentials = new HashSet<JGuardCredential>();

        //looking for missing credentials
        while (itCredentialFromTemplate.hasNext()) {
            JGuardCredential jcred = (JGuardCredential) itCredentialFromTemplate.next();
            Iterator itCredentialFromUser = credentialSetFromCandidate.iterator();
            boolean found = false;
            while (itCredentialFromUser.hasNext()) {
                JGuardCredential jcredFromUser = (JGuardCredential) itCredentialFromUser.next();
                //we are looking for the right credential id, but not the right value
                if (jcred.getName().equals(jcredFromUser.getName())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                missingCredentials.add(jcred);
            }
        }

        Set<JGuardCredential> credentialsNotRegistered = EntityTemplate.filterCredentialSet(credentialSetFromTemplate, credentialSetFromCandidate);
        if (credentialsNotRegistered.size() > 0) {
            logger.warn(" there are some unknown credentials filled by the user during the registration doFilter: ");
            logger.warn(credentialsNotRegistered.toString());
        }

        return missingCredentials;
    }


}
