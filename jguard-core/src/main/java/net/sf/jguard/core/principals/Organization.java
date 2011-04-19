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
package net.sf.jguard.core.principals;

import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * an organization which can own one {@link SubjectTemplate} .
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
public class Organization implements BasePrincipal, Cloneable {

    public static final String ID = "id";
    private SubjectTemplate subjectTemplate;
    /**
     * these objects are some references to principals present in the AuthenticationManager.
     * some of them can be owned by the Organization, which implies the ability to reorganize them,
     * but without overrule the set of permissions granted via all of its roles references.
     */
    protected Set<? extends Principal> principals;
    protected Set<JGuardCredential> credentials;
    protected Long id;
    protected Set users;


    @Override
    public Object clone() throws CloneNotSupportedException {
        Organization clonedOrg = (Organization) super.clone();
        Set<Principal> clonedPrincipals = PrincipalUtils.clonePrincipalsSet(principals);
        clonedOrg.setPrincipals(clonedPrincipals);

        Iterator<JGuardCredential> credentialsIterator = credentials.iterator();
        Set<JGuardCredential> clonedCredentials = new HashSet<JGuardCredential>();
        while (credentialsIterator.hasNext()) {
            JGuardCredential cred = credentialsIterator.next();
            clonedCredentials.add((JGuardCredential) cred.clone());
        }
        clonedOrg.setCredentials(clonedCredentials);
        clonedOrg.setSubjectTemplate((SubjectTemplate) subjectTemplate.clone());
        return clonedOrg;
    }

    /**
     * return a copy Set of the principals owned by this organization.
     *
     * @return
     */
    public Set<? extends Principal> getPrincipals() {
        return new HashSet<Principal>(principals);
    }

    public void setPrincipals(Set<? extends Principal> principals) {
        this.principals = principals;
    }

    @Override
    public boolean equals(Object organization) {

        if (!(organization instanceof Organization)) {
            return false;
        }
        Organization orga = (Organization) organization;
        Iterator itCred = this.credentials.iterator();
        JGuardCredential idCred = null;
        while (itCred.hasNext()) {
            JGuardCredential cred = (JGuardCredential) itCred.next();
            if (ID.equals(cred.getName())) {
                idCred = cred;
                break;
            }
        }
        return orga.getCredentials() != null && orga.getCredentials().contains(idCred);

    }

    @Override
    public int hashCode() {
        int i = super.hashCode();
        if (credentials != null) {
            i = credentials.hashCode();
        }
        return i;
    }


    public void removePrincipal(Principal principal) throws AuthenticationException {
        //remove this Principal
        // in the users which contains the Principal
        Collection u = getUsers();
        for (Object anU : u) {
            Subject user = (Subject) anU;
            Set ppals = user.getPrincipals();
            if (ppals.contains(principal)) {
                ppals.remove(principal);
            }
        }
        this.principals.remove(principal);


    }

    /**
     * return a <b>deep copy</b> of the subjectTemplate of the Organization.
     *
     * @return
     */
    public SubjectTemplate getSubjectTemplate() {
        try {
            return (SubjectTemplate) subjectTemplate.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    public void setSubjectTemplate(SubjectTemplate subjectTemplate) {
        OrganizationUtils.checkSubjectTemplatePrincipals(subjectTemplate, principals);
        this.subjectTemplate = subjectTemplate;
    }

    public Set getUsers() {
        return users;
    }


    public Set<JGuardCredential> getCredentials() {
        return credentials;
    }

    public void setCredentials(Set<JGuardCredential> credentials) {
        this.credentials = credentials;
    }

    /**
     * return the <b>unique</b> name of the organization.
     * this name is the value of the credentrial keyed by 'id'.
     *
     * @return name identifying the Organization
     */
    public String getName() {
        Iterator it = credentials.iterator();
        String credentialIdValue = "";
        while (it.hasNext()) {
            JGuardCredential cred = (JGuardCredential) it.next();
            if (cred.getName().equals(ID)) {
                credentialIdValue = (String) cred.getValue();
                break;
            }
        }
        return credentialIdValue;
    }

    public int compareTo(Object object) {
        if (object == null) {
            throw new IllegalArgumentException(" object comapred in the compareTo method of Organization class is null");
        }
        if (!(object instanceof Organization)) {
            throw new IllegalArgumentException("object is not an Orgnaization instance");
        }
        Organization o1 = (Organization) object;
        return getName().compareTo(o1.getName());
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setUsers(Set users) {
        this.users = users;
    }
}
