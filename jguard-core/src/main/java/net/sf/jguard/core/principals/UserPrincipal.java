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

import javax.security.auth.Subject;
import java.io.Serializable;
import java.security.Principal;
import java.util.*;

/**
 * UserPrincipal is used to resolve ABAC permissions.
 *
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class UserPrincipal implements Principal, Serializable {


    private static final String NO_NAME_FOUND = "NO NAME FOUND";
    private static final long serialVersionUID = 9075426017744650798L;
    private String name = "NO NAME DEFINED";
    private Subject subject;
    private static final int INT_FOR_HASH_CODE = 7;
    private static final int SECOND_INT_FOR_HASH_CODE = 23;

    public UserPrincipal(Subject subject) {
        this.subject = subject;
    }


    public void setName(String name) {
        this.name = name;

    }

    public Map getPrivateCredentials() {

        Set privateCredentials = getSubject().getPrivateCredentials();
        return transformCredentialSetIntoMap(privateCredentials);
    }

    private Map transformCredentialSetIntoMap(Set credentials) {
        Map pCredentials = new HashMap();
        for (Object credential : credentials) {
            if (credential instanceof JGuardCredential) {
                JGuardCredential jcred = (JGuardCredential) credential;
                if (!pCredentials.containsKey(jcred.getName())) {
                    Collection values = new HashSet();
                    values.add(jcred.getValue());
                    pCredentials.put(jcred.getName(), values);
                } else {
                    Collection valuesStored = (Collection) pCredentials.get(jcred.getName());
                    valuesStored.add(jcred.getValue());
                }

            }
        }
        return pCredentials;
    }

    public Map getPublicCredentials() {
        Set publicCredentials = getSubject().getPublicCredentials();
        return transformCredentialSetIntoMap(publicCredentials);
    }

    /**
     * @return the value of a credential present in the public credentials ' set
     *         of the Subject, if its 'id' is <i>"name"</i>.
     * @see net.sf.jguard.core.authentication.credentials.JGuardCredential
     */
    public String getName() {
        //we cannot add a more significant method to avoid infinite loop
        return NO_NAME_FOUND;
    }

    /**
     * compare two SubjectAsPrincipal objects(compare their Subject).
     *
     * @param object
     * @return true if the contained Subject is equals to the one contained
     *         in the SubjectAsPrincipal instance as parameter;otherwise, false.
     */
    @Override
    public boolean equals(Object object) {
        UserPrincipal userPrincipal;
        if (object instanceof UserPrincipal) {
            userPrincipal = (UserPrincipal) object;
            if (getPrincipals().equals(userPrincipal.getPrincipals())) {
                return true;
            }
            // we cannot include credentials in this method to avoid class circularity error
        }
        return false;

    }

    @Override
    public int hashCode() {
        int hash = INT_FOR_HASH_CODE;
        hash = SECOND_INT_FOR_HASH_CODE * hash + (this.name != null ? this.name.hashCode() : 0);
        return hash;
    }

    /**
     * return principals present in the subject except userPrincipals
     * to avoid infinite loop if we look into principals recursively.
     *
     * @return
     */
    Map getPrincipals() {

        //we filter userprincipal
        Set<Principal> principals = getSubject().getPrincipals();
        Set<Principal> filteredSet = new HashSet<Principal>();
        for (Principal principal : principals) {
            if (!(principal instanceof UserPrincipal)) {
                filteredSet.add(principal);
            }
        }

        //we transform set into map for jexl
        Map<String, Principal> ppals = new HashMap<String, Principal>();

        for (Principal aFilteredSet : filteredSet) {
            ppals.put(aFilteredSet.getName(), aFilteredSet);
        }

        return ppals;
    }


    /**
     * return {@link RolePrincipal} present in subject.
     *
     * @return
     */
    public Map getRoles() {
        return getSpecificPrincipals(RolePrincipal.class);
    }

    /**
     * return {@link RolePrincipal} present in subject.
     *
     * @return
     */
    public Organization getOrganization() {
        Set organizationSet = getSubject().getPrincipals(Organization.class);
        if (organizationSet.size() != 1) {
            throw new IllegalStateException(" a UserPrincipal object can contains only one organization. if no one is set, the default 'system' organization is used ");
        }
        return (Organization) organizationSet.iterator().next();
    }


    private Map getSpecificPrincipals(Class<? extends Principal> principalSubclass) {
        Set<? extends Principal> principals = getSubject().getPrincipals(principalSubclass);

        //we transform set into map for jexl
        Map<String, Principal> ppals = new HashMap<String, Principal>();

        for (Principal principal : principals) {
            ppals.put(principal.getName(), principal);
        }
        return ppals;
    }

    public int compareTo(Object o) {
        UserPrincipal principal = (UserPrincipal) o;
        if (this.equals(o)) {
            return 0;
        }

        return this.getName().compareTo(principal.getName());

    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UserPrincipal ");
        sb.append(name);
        sb.append(this.hashCode());
        return sb.toString();
    }


    public Subject getSubject() {
        return subject;
    }
}



