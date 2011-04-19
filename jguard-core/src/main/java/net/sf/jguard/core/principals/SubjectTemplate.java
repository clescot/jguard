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
package net.sf.jguard.core.principals;


import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.provisioning.RegistrationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * template used to validate user registration and to build the corresponding
 * Subject object.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
public class SubjectTemplate extends EntityTemplate {

    private static final Logger logger = LoggerFactory.getLogger(SubjectTemplate.class.getName());

    private Set<JGuardCredential> missingPrivateRequiredCred = new HashSet<JGuardCredential>();
    private Set<JGuardCredential> missingPublicRequiredCred = new HashSet<JGuardCredential>();
    private Set<JGuardCredential> unknownPrivateOptionalCred = new HashSet<JGuardCredential>();
    private Set<JGuardCredential> unknownPublicOptionalCred = new HashSet<JGuardCredential>();
    private Set<JGuardCredential> privateRequiredCredentials = new HashSet<JGuardCredential>();
    private Set<JGuardCredential> publicRequiredCredentials = new HashSet<JGuardCredential>();
    private Set<JGuardCredential> publicOptionalCredentials = new HashSet<JGuardCredential>();
    private Set<JGuardCredential> privateOptionalCredentials = new HashSet<JGuardCredential>();


    private Long id;
    //principals created during registration
    private Set<Principal> principals = new HashSet<Principal>();


    /**
     * remove unknown credentials and return missing credentials set.
     *
     * @param user
     * @return mssing credentials
     * @throws AuthenticationException
     */
    public Set validateRequiredCredentialsFromUser(Subject user) throws AuthenticationException {
        Set<JGuardCredential> missingCredentials = new HashSet<JGuardCredential>();
        Set credentialsNotRegistered = null;
        //we remove unknown credentials
        Set<JGuardCredential> userPublicRequiredCredentials = getCredentials(getPublicRequiredCredentials(), user.getPublicCredentials(JGuardCredential.class));
        Set<JGuardCredential> missingPublicCredentials = validateCredentialSet(getPublicRequiredCredentials(), userPublicRequiredCredentials);
        missingCredentials.addAll(missingPublicCredentials);

        Set<JGuardCredential> userPublicOptionalCredentials = getCredentials(getPublicOptionalCredentials(), user.getPublicCredentials(JGuardCredential.class));
        credentialsNotRegistered = filterCredentialSet(getPublicOptionalCredentials(), userPublicOptionalCredentials);
        if (credentialsNotRegistered.size() > 0) {
            logger.warn(" there are some unknown credentials filled by the user during the registration doFilter: ");
            logger.warn(credentialsNotRegistered.toString());
        }


        Set userPrivateRequiredCredentials = getCredentials(getPrivateRequiredCredentials(), user.getPrivateCredentials(JGuardCredential.class));
        Set<JGuardCredential> missingPrivateCredentials = validateCredentialSet(getPrivateRequiredCredentials(), userPrivateRequiredCredentials);
        missingCredentials.addAll(missingPrivateCredentials);

        Set<JGuardCredential> userPrivateOptionalCredentials = getCredentials(getPrivateOptionalCredentials(), user.getPrivateCredentials(JGuardCredential.class));
        credentialsNotRegistered = filterCredentialSet(getPrivateOptionalCredentials(), userPrivateOptionalCredentials);
        if (credentialsNotRegistered.size() > 0) {
            logger.warn(" there are some unknown credentials filled by the user during the registration doFilter: ");
            logger.warn(credentialsNotRegistered.toString());
        }

        return missingCredentials;
    }


    /**
     * build a Subject from a SubjectTemplate.
     *
     * @param user         SubjectTemplate used to build the Subject object
     * @param organization
     * @return subject built
     */
    public Subject toSubject(SubjectTemplate user, Organization organization) {

        Set<Principal> principalsForRegisteredUsers = new HashSet<Principal>();
        principalsForRegisteredUsers.addAll((getPrincipals()));

        //add to the user its organization
        principalsForRegisteredUsers.add(organization);

        Set publicCredentials = user.getPublicCredentials();
        Set privateCredentials = user.getPrivateCredentials();

        return new Subject(false, principalsForRegisteredUsers, publicCredentials, privateCredentials);
    }


    /**
     * build a Subject from a validated SubjectTemplate.
     *
     * @param organization
     * @return subject built
     */
    public Subject toSubject(Organization organization) {
        return toSubject(this, organization);
    }

    public final Set getMissingPublicRequiredCred() {
        return missingPublicRequiredCred;
    }

    public final Set getUnknownPrivateOptionalCred() {
        return unknownPrivateOptionalCred;
    }

    public final Set getUnknownPublicOptionalCred() {
        return unknownPublicOptionalCred;
    }

    /**
     * implements a deep copy of object
     *
     * @see java.lang.Object#clone()
     */
    public Object clone() throws CloneNotSupportedException {

        SubjectTemplate clone = (SubjectTemplate) super.clone();
        clone.setId(null);
        clone.setPrincipals(new HashSet<Principal>(principals));
        clone.setPrivateOptionalCredentials(JGuardCredential.cloneCredentialsSet(getPrivateOptionalCredentials()));
        clone.setPrivateRequiredCredentials(JGuardCredential.cloneCredentialsSet(getPrivateRequiredCredentials()));
        clone.setPublicOptionalCredentials(JGuardCredential.cloneCredentialsSet(getPublicOptionalCredentials()));
        clone.setPublicRequiredCredentials(JGuardCredential.cloneCredentialsSet(getPublicRequiredCredentials()));
        return clone;
    }

    /**
     * return a read-only SubjectTemplate.
     * this method is inspired from the
     * Collections.unmodifiableCollection(Collection c), which
     * is part of the JDK.
     *
     * @return read-only SubjectTemplate
     * @throws CloneNotSupportedException
     */
    public SubjectTemplate unmodifiableSubjectTemplate() throws CloneNotSupportedException {

        SubjectTemplate readOnly = (SubjectTemplate) this.clone();

        //principal stuff
        readOnly.principals = (Collections.unmodifiableSet(principals));

        //credential stuff
        readOnly.setPrivateOptionalCredentials((Collections.unmodifiableSet(getPrivateOptionalCredentials())));
        readOnly.setPrivateRequiredCredentials((Collections.unmodifiableSet(getPrivateRequiredCredentials())));
        readOnly.setPublicOptionalCredentials(((Collections.unmodifiableSet(getPublicOptionalCredentials()))));
        readOnly.setPublicRequiredCredentials((Collections.unmodifiableSet(getPublicRequiredCredentials())));

        return readOnly;
    }


    public final Set<JGuardCredential> getMissingPrivateRequiredCred() {
        return missingPrivateRequiredCred;
    }

    public void setPrivateRequiredCredentials(Set<JGuardCredential> privateCredentials) {
        this.privateRequiredCredentials = privateCredentials;
    }

    public void setPublicRequiredCredentials(Set<JGuardCredential> publicCredentials) {
        this.publicRequiredCredentials = publicCredentials;
    }

    public Set<JGuardCredential> getPrivateOptionalCredentials() {
        return privateOptionalCredentials;
    }

    public void setPrivateOptionalCredentials(Set<JGuardCredential> privateOptionalCredentials) {
        this.privateOptionalCredentials = privateOptionalCredentials;
    }

    public Set<JGuardCredential> getPublicOptionalCredentials() {
        return publicOptionalCredentials;
    }

    public void setPublicOptionalCredentials(Set<JGuardCredential> publicOptionalCredentials) {
        this.publicOptionalCredentials = publicOptionalCredentials;
    }

    public Set<JGuardCredential> getPublicRequiredCredentials() {
        return publicRequiredCredentials;
    }

    public Set<JGuardCredential> getPrivateRequiredCredentials() {
        return privateRequiredCredentials;
    }

    Set<JGuardCredential> getPublicCredentials() {
        Set<JGuardCredential> publicCredentials = getPublicOptionalCredentials();
        publicCredentials.addAll(getPublicRequiredCredentials());
        return publicCredentials;
    }


    Set<JGuardCredential> getPrivateCredentials() {
        Set<JGuardCredential> privateCredentials = getPrivateOptionalCredentials();
        privateCredentials.addAll(getPrivateRequiredCredentials());
        return privateCredentials;

    }

    public Set<JGuardCredential> getRequiredCredentials() {
        Set<JGuardCredential> requiredCredentials = new HashSet<JGuardCredential>(getPublicRequiredCredentials());
        requiredCredentials.addAll(getPrivateRequiredCredentials());
        return requiredCredentials;
    }

    /**
     * validate the EntityTemplate candidate.
     *
     * @param candidate the subjectTemplate which is candidate
     *                  to be transformed into a Subject object.
     * @throws AuthenticationException when the user does not content mandatory fields
     * @throws net.sf.jguard.core.provisioning.RegistrationException
     *
     */
    public void validateTemplate(SubjectTemplate candidate) throws RegistrationException {

        if (candidate.getPrivateRequiredCredentials() == null) {
            logger.warn("private required credentials set from user is null ");
            candidate.setPrivateRequiredCredentials(new HashSet<JGuardCredential>());
        }
        if (candidate.getPrivateOptionalCredentials() == null) {
            logger.warn("private optional credentials set from user is null ");
            candidate.setPrivateOptionalCredentials(new HashSet<JGuardCredential>());
        }
        if (candidate.getPublicRequiredCredentials() == null) {
            logger.warn("public required credentials set from user is null ");
            candidate.setPublicRequiredCredentials(new HashSet<JGuardCredential>());
        }
        if (candidate.getPublicOptionalCredentials() == null) {
            logger.warn("public optional credentials set from user is null ");
            candidate.setPublicOptionalCredentials(new HashSet<JGuardCredential>());
        }

        missingPrivateRequiredCred =
                validateCredentialSet(getPrivateRequiredCredentials(), candidate.getPrivateRequiredCredentials());
        if (missingPrivateRequiredCred.size() > 0) {
            throw new RegistrationException("missing private credentials required :" + missingPrivateRequiredCred, new HashSet(), missingPrivateRequiredCred);
        }

        missingPublicRequiredCred =
                validateCredentialSet(getPublicRequiredCredentials(), candidate.getPublicRequiredCredentials());
        if (missingPublicRequiredCred.size() > 0) {
            throw new RegistrationException("missing public credentials required :" + missingPublicRequiredCred, missingPublicRequiredCred, new HashSet());
        }

        unknownPrivateOptionalCred =
                filterCredentialSet(getPrivateOptionalCredentials(), candidate.getPrivateOptionalCredentials());
        if (unknownPrivateOptionalCred.size() > 0) {
            logger.warn(" user has filled unknown optional private credentials :");
            logger.warn(unknownPrivateOptionalCred.toString());
        }
        unknownPublicOptionalCred =
                filterCredentialSet(getPublicOptionalCredentials(), candidate.getPublicOptionalCredentials());
        if (unknownPublicOptionalCred.size() > 0) {
            logger.warn(" user has filled unknown optional public credentials :");
            logger.warn(unknownPublicOptionalCred.toString());
        }
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }


    public Set<? extends Principal> getPrincipals() {
        return principals;
    }

    /**
     * defined the principals automatically granted to the registered user.
     *
     * @param principals
     */
    public void setPrincipals(Set<Principal> principals) {
        this.principals = principals;
    }

}
