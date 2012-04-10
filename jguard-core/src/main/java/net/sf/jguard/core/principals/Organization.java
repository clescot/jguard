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
package net.sf.jguard.core.principals;

import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * an organization which can own one {@link SubjectTemplate} .
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
public class Organization implements BasePrincipal, Cloneable {

    public static final String ID = "id";
    private static final Logger logger = LoggerFactory.getLogger(Organization.class.getName());
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
        Set<Principal> clonedPrincipals = clonePrincipalsSet(principals);
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
        checkSubjectTemplatePrincipals(subjectTemplate);
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

    /**
     * like multiple role inheritance can be enabled, we should check that
     * every Permissions Set owned by the generic candidate principal is not
     * a superset of the Permissions Set owned by Principals of the Organization.
     * in this case, we remove principals which exceed grants owned by the organisation.
     *
     * @param template SubjectTemplate to filter
     */
    private void checkSubjectTemplatePrincipals(SubjectTemplate template) {
        if (principals == null) {
            throw new IllegalStateException(" no principals have been defined for this organization." +
                    " validation of a subjectTemplate cannot be done against an empty principal list ");
        }
        Iterator<? extends Principal> itPrincipalsOwned = principals.iterator();
        Set globalPermissions = new HashSet();
        //we make the globalPermissions Set
        while (itPrincipalsOwned.hasNext()) {
            PermissionContainer tempPrincipal = (PermissionContainer) itPrincipalsOwned.next();
            globalPermissions.addAll(tempPrincipal.getAllPermissions());
        }

        //check principals from template
        Set principalsFromTemplate = template.getPrincipals();
        checkPrincipals(globalPermissions, principalsFromTemplate);

    }

    /**
     * clone deeply a set of {@link net.sf.jguard.core.principals.BasePrincipal} subclasses instances.
     *
     * @param principals
     * @return
     * @throws CloneNotSupportedException
     */
    public static Set<Principal> clonePrincipalsSet(Set<? extends Principal> principals) throws CloneNotSupportedException {
        Set<Principal> clonedPrincipals = new HashSet<Principal>();
        for (Principal principal : principals) {
            BasePrincipal ppal = (BasePrincipal) principal;
            clonedPrincipals.add((Principal) ppal.clone());
        }
        return clonedPrincipals;
    }

    /**
     * check principal Set against global Permissions.
     *
     * @param globalPermissions
     * @param principals
     */
    private static void checkPrincipals(Set globalPermissions, Set<PermissionContainer> principals) {
        Iterator<PermissionContainer> itPrincipals = principals.iterator();
        while (itPrincipals.hasNext()) {
            PermissionContainer tempPrincipal = itPrincipals.next();
            Set permissionsFromTemplate = tempPrincipal.getAllPermissions();
            if (!globalPermissions.containsAll(permissionsFromTemplate)) {
                //we remove this principal which contains permissions not present in globalPermissions
                logger.warn(" principal called " + tempPrincipal.getName() + " has been removed from the SubjectTemplate ");
                logger.warn(" because it contains permissions not owned by this organization throw its Principals ");
                itPrincipals.remove();
            }

        }
    }

}
