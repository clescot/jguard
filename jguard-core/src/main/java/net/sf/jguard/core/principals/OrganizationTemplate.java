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

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

/**
 * a candidate to be an {@link Organization}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class OrganizationTemplate extends EntityTemplate {

    private Set<JGuardCredential> credentials;

    private SubjectTemplate subjectTemplate;
    private Long id;
    public static final String ORGANIZATION_TEMPLATE = "organizationTemplate";
    private Set<? extends Principal> principals;

    public OrganizationTemplate() {
        super();
        credentials = new HashSet<JGuardCredential>();
        subjectTemplate = new SubjectTemplate();
        principals = new HashSet<Principal>();
    }

    public OrganizationTemplate(Organization organization) {
        super();
        credentials = new HashSet<JGuardCredential>(organization.getCredentials());
        principals = organization.getPrincipals();
        subjectTemplate = organization.getSubjectTemplate();
        principals = new HashSet<Principal>();
    }


    /**
     * build an Organization from a validated OrganizationTemplate.
     *
     * @param orga organization to convert to an Organization instace
     * @return Organization built
     */
    public Organization buildOrganization(OrganizationTemplate orga) {

        Set<Principal> principalsForRegisteredUsers = new HashSet<Principal>();
        principalsForRegisteredUsers.addAll((getPrincipals()));
        Set<JGuardCredential> creds = new HashSet<JGuardCredential>(orga.getCredentials());
        Set<Principal> principalsForOrganization = new HashSet<Principal>();
        //we add the principals from our organizationTemplate
        principalsForOrganization.addAll((getPrincipals()));
        Organization organization = new Organization();
        organization.setCredentials(creds);
        organization.setPrincipals(principalsForOrganization);
        organization.setSubjectTemplate(orga.getSubjectTemplate());
        return organization;
    }

    /**
     * build a Subject from a validated SubjectTemplate.
     *
     * @return subject built
     */
    public Organization toOrganization() {
        return buildOrganization(this);
    }


    /**
     * @param organizationCandidate
     */
    public void validateTemplate(OrganizationTemplate organizationCandidate) {
        if (organizationCandidate == null) {
            throw new IllegalArgumentException(" organizationTemplate is null ");
        }
        Set requiredCredentialsFromCandidate = organizationCandidate.getCredentials();
        if (requiredCredentialsFromCandidate == null) {
            requiredCredentialsFromCandidate = new HashSet();
            organizationCandidate.setCredentials(requiredCredentialsFromCandidate);
        }
        EntityTemplate.filterCredentialSet(this.credentials, requiredCredentialsFromCandidate);

    }

    public SubjectTemplate getSubjectTemplate() {
        return subjectTemplate;
    }

    public void setSubjectTemplate(SubjectTemplate subjectTemplate) {
        this.subjectTemplate = subjectTemplate;
    }

    public Set<JGuardCredential> getCredentials() {
        return credentials;
    }

    public void setCredentials(Set credentials) {
        this.credentials = credentials;
    }

    public Object clone() throws CloneNotSupportedException {
        OrganizationTemplate clone = (OrganizationTemplate) super.clone();
        clone.setSubjectTemplate((SubjectTemplate) subjectTemplate.clone());
        clone.setPrincipals(Organization.clonePrincipalsSet(principals));
        clone.setCredentials(JGuardCredential.cloneCredentialsSet(credentials));
        return clone;
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
    public void setPrincipals(Set principals) {
        this.principals = principals;
    }


}
