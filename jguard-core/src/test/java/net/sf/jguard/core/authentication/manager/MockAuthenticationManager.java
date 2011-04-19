package net.sf.jguard.core.authentication.manager;

import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.principals.Organization;
import net.sf.jguard.core.principals.OrganizationTemplate;
import net.sf.jguard.core.principals.SubjectTemplate;
import net.sf.jguard.core.provisioning.RegistrationException;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.Collection;
import java.util.Set;

public class MockAuthenticationManager implements AuthenticationManager {


    public Organization createOrganization(OrganizationTemplate organizationTemplate) throws RegistrationException {
        return null;
    }

    public void deleteOrganization(Organization organisation) {

    }

    public Organization getDefaultOrganization() {
        return null;
    }

    public Set<Organization> getOrganizations() throws AuthenticationException {
        return null;
    }

    public void updateOrganization(String organizationIdentityCredential, Organization organisation) throws AuthenticationException {

    }

    public Organization findOrganization(String organizationId) {
        return null;
    }

    public String getCredentialId() {
        return null;
    }

    public String getCredentialPassword() {
        return null;
    }

    public void createPrincipal(Principal role) throws AuthenticationException {

    }

    public Subject createUser(SubjectTemplate user, Organization organization) throws RegistrationException {
        return null;
    }

    public Subject createUser(Subject user, Organization organization) throws AuthenticationException {
        return null;
    }

    public Principal getLocalPrincipal(String name) throws AuthenticationException {
        return null;
    }

    public Set<Principal> getAllPrincipalsSet() throws AuthenticationException {
        return null;
    }

    public Set<Principal> getLocalPrincipals() {
        return null;
    }

    public Set<Subject> findUsers(Collection<JGuardCredential> privateCredentials, Collection<JGuardCredential> publicCredentials) throws AuthenticationException {
        return null;
    }

    public boolean userAlreadyExists(Subject user) throws AuthenticationException {
        return false;
    }

    public boolean hasPrincipal(Principal role) throws AuthenticationException {
        return false;
    }

    public boolean hasPrincipal(String role) throws AuthenticationException {
        return false;
    }

    public void updateUser(JGuardCredential identityCred, Subject user) throws AuthenticationException {

    }

    public void deleteUser(Subject user) throws AuthenticationException {

    }

    public OrganizationTemplate getOrganizationTemplate() throws AuthenticationException {
        return null;
    }

    public void setOrganizationTemplate(OrganizationTemplate organizationTemplate) throws AuthenticationException {

    }

    public Set<Subject> getUsers() throws AuthenticationException {
        return null;
    }

    public boolean isEmpty() {
        return false;
    }

    public void updatePrincipal(String oldPrincipalName, Principal principal) throws AuthenticationException {

    }

    public boolean deletePrincipal(Principal principal) throws AuthenticationException {
        return false;
    }

    public Principal clonePrincipal(String roleName) throws AuthenticationException {
        return null;
    }

    public Principal clonePrincipal(String roleName, String cloneName) throws AuthenticationException {
        return null;
    }

    public void setActiveOnRolePrincipal(Subject subject, String roleName, String applicationName, boolean active) throws AuthenticationException {

    }

    public Subject findUser(String login) {
        return null;
    }

    public void updateRoleDefinition(Subject subject, String role, String applicationName, String definition) throws AuthenticationException {

    }

    public void importAuthenticationManager(AuthenticationManager authManager) {

    }

    public String getApplicationName() {
        return null;
    }
}
