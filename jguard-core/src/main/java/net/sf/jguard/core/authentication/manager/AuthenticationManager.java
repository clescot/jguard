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
package net.sf.jguard.core.authentication.manager;


import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.principals.Organization;
import net.sf.jguard.core.principals.OrganizationTemplate;
import net.sf.jguard.core.principals.SubjectTemplate;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.Collection;
import java.util.Set;

/**
 * this interface provide the ability to operate on the system which stores user profiles.
 * it can be a database, or an ldap server, or anything else....
 * it concerns <strong>administrators</strong> guys.
 * there is one AuthenticationManager per webapp.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
public interface AuthenticationManager {

    /**
     * root organization name.
     */
    String SYSTEM = "system";

    Organization createOrganization(OrganizationTemplate organizationTemplate);

    void deleteOrganization(Organization organisation);

    /**
     * return the <i>default</i> Organization identified by the id <b>system</b>.
     *
     * @return
     */
    Organization getDefaultOrganization();

    Set<Organization> getOrganizations();

    void updateOrganization(String organizationIdentityCredential, Organization organisation);

    /**
     * @param organizationId unique to find
     * @return Organization found or <b>null</b> otherwise.
     */
    Organization findOrganization(String organizationId);

    /**
     * 'name' value of the <b>public</b> jGuardCredential owning the login value.
     *
     * @return
     */
    String getCredentialId();


    /**
     * name value of the {@link JGuardCredential} owning the 'password' value.
     * this credential is present in the <b>private</b> set of the {@link javax.security.auth.Subject}.
     *
     * @return
     */
    String getCredentialPassword();


    /**
     * add principals in the list to the persistance storage.
     * create a Principal in the backend, <strong>only</strong> if it is not already present.
     *
     * @param role
     * @throws AuthenticationException
     */
    void createPrincipal(Principal role);

    /**
     * @param user         to be controlled
     * @param organization is the validator
     * @return
     * @throws net.sf.jguard.core.provisioning.RegistrationException
     *
     */
    Subject createUser(SubjectTemplate user, Organization organization);

    /**
     * @param user         to be controlled
     * @param organization is the validator
     * @return
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    Subject createUser(Subject user, Organization organization);

    /**
     * retrieve role from the webapp.
     *
     * @param name
     * @return roleInterface
     * @throws AuthenticationException
     */
    Principal getLocalPrincipal(String name);


    /**
     * get an <b>unmodifiable</b> set of the principals defined in the repository for all the applications.
     *
     * @return role's list.
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    Set<Principal> getAllPrincipalsSet();

    /**
     * get the principals defined in the repository <strong>only</strong> for this application.
     *
     * @return role's list.
     */
    Set<Principal> getLocalPrincipals();

    /**
     * retrieve users which are in conformance with all these credentials.
     *
     * @param privateCredentials private attributes of the user
     * @param publicCredentials  public attributes of the user
     * @return users
     * @throws AuthenticationException
     */
    Set<Subject> findUsers(Collection<JGuardCredential> privateCredentials, Collection<JGuardCredential> publicCredentials);

    /**
     * checks if a user with the same username already exists.
     *
     * @param user user seek
     * @return result. true if a user with the same name exists, false otherwise.
     * @throws AuthenticationException
     */
    boolean userAlreadyExists(Subject user);


    /**
     * role wether or not exists in the webapp.
     *
     * @param role to check
     * @return result
     * @throws AuthenticationException
     */
    boolean hasPrincipal(Principal role);

    /**
     * role wether or not exists in the webapp.
     *
     * @param role to check
     * @return result
     * @throws AuthenticationException
     */
    boolean hasPrincipal(String role) throws AuthenticationException;

    /**
     * update user's informations.
     *
     * @param identityCred
     * @param user
     * @throws AuthenticationException
     */
    void updateUser(JGuardCredential identityCred, Subject user);

    /**
     * remove user.
     *
     * @param user
     * @throws AuthenticationException
     */
    void deleteUser(Subject user);

    /**
     * return the OrganizationTemplate.
     *
     * @return OrganizationTemplate
     * @throws AuthenticationException
     */
    OrganizationTemplate getOrganizationTemplate();

    void setOrganizationTemplate(OrganizationTemplate organizationTemplate);


    Set<Subject> getUsers();

    boolean isEmpty();

    /**
     * change principal's name.
     *
     * @param oldPrincipalName
     * @param principal
     * @throws AuthenticationException
     */
    void updatePrincipal(String oldPrincipalName, Principal principal);


    /**
     * delete this principal and its references in users.
     *
     * @param principal
     * @return false i delete fails, true if it succeed
     * @throws AuthenticationException
     */
    boolean deletePrincipal(Principal principal);


    /**
     * Clone a Principal with a random name
     *
     * @param roleName Principal name to clone
     * @return cloned Principal with a different name: roleName + Random integer betweeen 0 and 99999
     * @throws AuthenticationException
     */
    Principal clonePrincipal(String roleName);

    /**
     * Clone a Principal. If Principal is instance of RolePrincipal makes a call to the clone method
     *
     * @param roleName  Principal name to clone
     * @param cloneName Principal cloned name
     * @return cloned Principal with the given cloneName
     * @throws AuthenticationException
     */
    Principal clonePrincipal(String roleName, String cloneName);

    /**
     * change 'active' property on the specified role for a user.
     * this change cannot be done on 'guest' user, or if it remains only one 'active=true' role.
     *
     * @param subject         user owning the role to activate
     * @param roleName        role name to activate
     * @param applicationName application name owning the role
     * @param active          true for active, false for inactive
     * @throws AuthenticationException
     */
    void setActiveOnRolePrincipal(Subject subject, String roleName, String applicationName, boolean active);

    Subject findUser(String login);

    void updateRoleDefinition(Subject subject, String role, String applicationName, String definition);


    void importAuthenticationManager(AuthenticationManager authManager);


    /**
     * return the name of the <strong>current</strong> application which holds this
     * AuthenticationManager.
     *
     * @return
     */
    String getApplicationName();
}
