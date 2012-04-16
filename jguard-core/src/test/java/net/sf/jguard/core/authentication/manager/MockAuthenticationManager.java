package net.sf.jguard.core.authentication.manager;

import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.principals.Organization;
import net.sf.jguard.core.principals.OrganizationTemplate;
import net.sf.jguard.core.principals.SubjectTemplate;
import net.sf.jguard.core.provisioning.RegistrationException;

import javax.inject.Inject;
import javax.security.auth.Subject;
import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class MockAuthenticationManager extends AbstractAuthenticationManager implements AuthenticationManager {

    Set<Subject> subjects = new HashSet<Subject>();

    @Inject
    public MockAuthenticationManager(@ApplicationName String applicationName) {
        super(applicationName);
        subjects.add(getGuestSubject());
    }

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
        return "login";
    }

    public String getCredentialPassword() {
        return "password";
    }

    public void createPrincipal(Principal role) throws AuthenticationException {

    }

    @Override
    protected void persistUser(Subject user) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    protected void persistPrincipal(Principal principal) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    protected void persistOrganization(Organization organization) throws AuthenticationException {
        //To change body of implemented methods use File | Settings | File Templates.
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

    @Override
    protected void updateUserImpl(JGuardCredential identityCred, Subject user) throws AuthenticationException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void deleteUser(Subject user) throws AuthenticationException {

    }

    public OrganizationTemplate getOrganizationTemplate() throws AuthenticationException {
        return null;
    }

    public void setOrganizationTemplate(OrganizationTemplate organizationTemplate) throws AuthenticationException {

    }

    public Set<Subject> getUsers() throws AuthenticationException {

        return subjects;
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
