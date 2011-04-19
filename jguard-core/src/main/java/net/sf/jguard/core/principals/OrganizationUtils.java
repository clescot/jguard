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


import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * utility class for {@link Organization}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public final class OrganizationUtils {


    private OrganizationUtils() {

    }


    /**
     * find the first organization with an id equals to the organizationId param
     *
     * @param organizations  collection used to search organization
     * @param organizationId id of the organization
     * @return first organization found or null if no one is found
     * @throws IllegalArgumentException
     */
    public static Organization findOrganization(Collection<Organization> organizations, String organizationId) throws IllegalArgumentException {
        Organization organization = null;
        for (Organization orga : organizations) {
            if (organizationId.equals(orga.getName())) {
                organization = orga;
                break;
            }
        }
        if (organization == null) {
            throw new IllegalArgumentException("organization not found with id=" + organizationId);
        }
        return organization;
    }

    /**
     * like multiple role inheritance can be enabled, we should check that
     * every Permissions Set owned by the generic candidate principal is not
     * a superset of the Permissions Set owned by Principals of the Organization.
     * in this case, we remove principals which exceed grants owned by the organisation.
     *
     * @param template SubjectTemplate to filter
     * @param ppals
     */
    public static void checkSubjectTemplatePrincipals(SubjectTemplate template, Set<? extends Principal> ppals) {
        if (ppals == null) {
            throw new IllegalStateException(" no principals have been defined for this organization." +
                    " validation of a subjectTemplate cannot be done against an empty principal list ");
        }
        Iterator<? extends Principal> itPrincipalsOwned = ppals.iterator();
        Set globalPermissions = new HashSet();
        //we make the globalPermissions Set
        while (itPrincipalsOwned.hasNext()) {
            RolePrincipal tempPrincipal = (RolePrincipal) itPrincipalsOwned.next();
            globalPermissions.addAll(tempPrincipal.getAllPermissions());
        }

        //check principals from template
        Set principalsFromTemplate = template.getPrincipals();
        PrincipalUtils.checkPrincipals(globalPermissions, principalsFromTemplate);

    }


}
