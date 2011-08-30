/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
package net.sf.jguard.ext.principals;


import net.sf.jguard.core.principals.Organization;
import net.sf.jguard.core.principals.SubjectTemplate;
import org.hibernate.Session;

import javax.inject.Provider;
import java.util.Set;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class PersistedOrganization extends Organization {

    private PersistedSubjectTemplate persistedSubjectTemplate;

    public PersistedOrganization() {
        super();
    }

    public PersistedOrganization(Organization organization,Provider<Session> sessionProvider) {
        super();

        this.id = organization.getId();
        this.principals = new HibernatePrincipalUtils(sessionProvider).getPersistedPrincipals(organization.getPrincipals());
        this.persistedSubjectTemplate = new PersistedSubjectTemplate(organization.getSubjectTemplate(),sessionProvider);

        this.credentials = organization.getCredentials();
        this.users = organization.getUsers();

    }


    /**
     * transform persistedOrganization into an organization with java.security.Principal subclasses instances
     * and a SubjectTemplate containing also some java.security.Principal subclassses instances.
     * so, in this method, Principal used for persistance (internal use) is transformed into a java.security.Principal subclass
     * for external use.
     *
     * @return
     */
    public Organization toOrganization() {

        Organization orga = new Organization();
        orga.setId(getId());
        orga.setPrincipals(HibernatePrincipalUtils.getjavaSecurityPrincipals((Set<PersistedPrincipal>) getPrincipals()));
        orga.setCredentials(getCredentials());
        SubjectTemplate st = persistedSubjectTemplate.toSubjectTemplate();
        orga.setSubjectTemplate(st);
        orga.setUsers(getUsers());
        return orga;
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof PersistedOrganization)) {
            return false;
        }

        final PersistedOrganization porganization = (PersistedOrganization) other;
        return getPersistedSubjectTemplate().equals(porganization.getPersistedSubjectTemplate()) &&
                credentials.equals(porganization.getCredentials()) &&
                principals.equals(porganization.getPrincipals());
    }

    public int hashCode() {
        int hash = 7;
        hash = 23 * hash + (this.persistedSubjectTemplate != null ? this.persistedSubjectTemplate.hashCode() : 0);
        hash = 23 * hash + (this.credentials != null ? this.credentials.hashCode() : 0);
        hash = 23 * hash + (this.principals != null ? this.principals.hashCode() : 0);
        return hash;
    }

    public PersistedSubjectTemplate getPersistedSubjectTemplate() {
        return persistedSubjectTemplate;
    }

    public void setPersistedSubjectTemplate(PersistedSubjectTemplate persistedSubjectTemplate) {
        this.persistedSubjectTemplate = persistedSubjectTemplate;
    }

} 

