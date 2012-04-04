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
package net.sf.jguard.ext.principals;

import com.google.inject.Provider;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.util.SubjectUtils;
import org.hibernate.Session;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

/**
 * POJO part of {@link javax.security.auth.Subject}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class PersistedSubject {

    private Set<PersistedPrincipal> principals;
    private Set<JGuardCredential> publicCredentials;
    private Set<JGuardCredential> privateCredentials;
    private Long id;
    private PersistedOrganization persistedOrganization;
    private String login = null;
    private boolean active = true;
    public static final String LOGIN = "login";
    public static final String ACTIVE = "active";
    public final static String PERSISTENCE_ID = "persistenceId";
    private static final String ZERO = "0";
    private Provider<Session> sessionProvider;

    PersistedSubject() {

    }

    public PersistedSubject(Subject subject, PersistedOrganization organization, Provider<Session> sessionProvider) {
        this.sessionProvider = sessionProvider;

        //grab the persistence id from jguardCredentials to set it directly in the class
        String idToString = SubjectUtils.getCredentialValueAsString(subject, false, PERSISTENCE_ID);
        if (idToString != null && !idToString.equals("")) {
            id = new Long(idToString);
        }
        persistedOrganization = organization;
        update(subject);


    }

    public void update(Subject subject) {
        privateCredentials = subject.getPrivateCredentials(JGuardCredential.class);

        //remove the jguardCredential owning the persistence id
        privateCredentials.remove(new JGuardCredential(PERSISTENCE_ID, id));

        publicCredentials = subject.getPublicCredentials(JGuardCredential.class);
        //login is  always part of the <b>public</b>  credentials
        login = SubjectUtils.getCredentialValueAsString(subject, true, LOGIN);
        publicCredentials.remove(new JGuardCredential(LOGIN, getLogin()));

        active = Boolean.valueOf(SubjectUtils.getCredentialValueAsString(subject, false, ACTIVE));
        privateCredentials.remove(new JGuardCredential(ACTIVE, active));


        principals = new HibernatePrincipalUtils(sessionProvider).getPersistedPrincipals(subject.getPrincipals());

    }

    public javax.security.auth.Subject toJavaxSecuritySubject() {
        Set<Principal> ppals = HibernatePrincipalUtils.getjavaSecurityPrincipals(principals);
        if (id != null && !id.toString().equals(ZERO)) {
            //this credential is used to keep track of the database row in an Object not related with database in its API
            //so, the final user should not keep an eye on it 
            JGuardCredential persistanceIdCredential = new JGuardCredential(PERSISTENCE_ID, id.toString());
            privateCredentials.add(persistanceIdCredential);
        }
        Set<Principal> clonedPrincipals = new HashSet<Principal>(ppals);
        clonedPrincipals.add(persistedOrganization.toOrganization());
        HashSet<JGuardCredential> privCredentials = new HashSet<JGuardCredential>(privateCredentials);
        HashSet<JGuardCredential> pubCredentials = new HashSet<JGuardCredential>(publicCredentials);
        pubCredentials.add(new JGuardCredential(LOGIN, getLogin()));
        privCredentials.add(new JGuardCredential(ACTIVE, Boolean.toString(active)));
        return new javax.security.auth.Subject(false, clonedPrincipals, pubCredentials, privCredentials);
    }

    Set<PersistedPrincipal> getPrincipals() {
        return principals;
    }

    public void setPrincipals(Set<PersistedPrincipal> principals) {
        this.principals = principals;
    }

    public Set<JGuardCredential> getPublicCredentials() {
        return publicCredentials;
    }

    public void setPublicCredentials(Set<JGuardCredential> publicCredentials) {
        this.publicCredentials = publicCredentials;
    }

    public Set<JGuardCredential> getPrivateCredentials() {
        return privateCredentials;
    }

    public void setPrivateCredentials(Set<JGuardCredential> privateCredentials) {
        this.privateCredentials = privateCredentials;
    }

    public Long getId() {
        return id;
    }


    private void setId(Long id) {
        this.id = id;
    }

    public PersistedOrganization getOrganization() {
        return persistedOrganization;
    }

    public void setOrganization(PersistedOrganization organization) {
        this.persistedOrganization = organization;
    }

    public int hashCode() {
        int hash = 3;
        hash = 79 * hash + (this.principals != null ? this.principals.hashCode() : 0);
        hash = 79 * hash + (this.publicCredentials != null ? this.publicCredentials.hashCode() : 0);
        hash = 79 * hash + (this.privateCredentials != null ? this.privateCredentials.hashCode() : 0);
        hash = 79 * hash + (this.persistedOrganization != null ? this.persistedOrganization.hashCode() : 0);
        hash = 79 * hash + (this.getLogin() != null ? this.getLogin().hashCode() : 0);
        return hash;
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof PersistedSubject)) {
            return false;
        }

        final PersistedSubject psubject = (PersistedSubject) other;
        return principals.equals(psubject.getPrincipals()) &&
                privateCredentials.equals(psubject.getPrivateCredentials()) &&
                publicCredentials.equals(psubject.getPublicCredentials()) &&
                persistedOrganization.equals(psubject.getOrganization());
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

}
