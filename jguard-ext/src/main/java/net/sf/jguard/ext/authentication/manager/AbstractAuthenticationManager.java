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
package net.sf.jguard.ext.authentication.manager;

import net.sf.jguard.core.authentication.callbacks.GuestCallbacksProvider;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.principals.*;
import net.sf.jguard.core.provisioning.RegistrationException;
import net.sf.jguard.core.util.SubjectUtils;
import net.sf.jguard.core.util.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.util.*;


/**
 * Abstract class which provides convenient methods for all the
 * AuthenticationManager implementations.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
public abstract class AbstractAuthenticationManager implements AuthenticationManager {

    private static final Logger logger = LoggerFactory.getLogger(AbstractAuthenticationManager.class.getName());


    protected OrganizationTemplate organizationTemplate;

    private final static String credentialId = "login";
    private final static String credentialPassword = "password";
    protected Organization defaultOrganization = null;
    protected String applicationName;


    //principals owned by the application
    protected Set<Principal> localPrincipalsSet;
    protected Map<String, Principal> localPrincipals;
    protected Set<Organization> organizations;
    private static final String J_GUARD_USERS_PRINCIPALS_XML = "/" + "jGuardUsersPrincipals.xml";
    private static final char SLASH = '/';
    public final static String AUTHENTICATION_XML_FILE_LOCATION = "authenticationXmlFileLocation";

    public AbstractAuthenticationManager(String applicationName) {
        super();
        localPrincipalsSet = new HashSet<Principal>();
        localPrincipals = new HashMap<String, Principal>();
        organizations = new HashSet<Organization>();
        this.applicationName = applicationName;
    }

    public String getApplicationName() {
        return applicationName;
    }


    protected void importXmlData(URL dbPropertiesLocation) {

        if (dbPropertiesLocation == null) {
            throw new IllegalArgumentException(AUTHENTICATION_XML_FILE_LOCATION + " parameter =null");
        }
        String dbPath;
        try {
            dbPath = XMLUtils.resolveLocation(dbPropertiesLocation.toURI().toString());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }


        String xmlFileLocation = dbPath.substring(0, dbPath.lastIndexOf(SLASH))
                + J_GUARD_USERS_PRINCIPALS_XML;
        URL url;
        try {
            url = new URL(XMLUtils.resolveLocation(xmlFileLocation));
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        AuthenticationManager authentManager = new XmlAuthenticationManager(applicationName, url);
        importAuthenticationManager(authentManager);

    }

    public Organization getDefaultOrganization() {
        //we check that a default organization exists
        if (defaultOrganization == null) {
            defaultOrganization = findOrganization(SYSTEM);
        }
        //if no default organization exists, we create a default organization
        if (defaultOrganization == null) {
            try {
                OrganizationTemplate orgTemplate = (OrganizationTemplate) getOrganizationTemplate().clone();
                Set<JGuardCredential> credentials = orgTemplate.getCredentials();
                Iterator itCredentials = credentials.iterator();
                while (itCredentials.hasNext()) {
                    JGuardCredential cred = (JGuardCredential) itCredentials.next();
                    if (cred.getName().equals(Organization.ID)) {
                        itCredentials.remove();
                        break;
                    }
                }
                JGuardCredential credId = new JGuardCredential(Organization.ID, SYSTEM);
                credentials.add(credId);
                defaultOrganization = createOrganization(orgTemplate);
            } catch (CloneNotSupportedException ex) {
                throw new RuntimeException(ex.getMessage(), ex);
            } catch (RegistrationException ex) {
                throw new RuntimeException(" default organization called 'system' is not present and cannot be created automatically ", ex);
            }
        }
        return defaultOrganization;
    }

    public abstract void setOrganizationTemplate(OrganizationTemplate organizationTemplate);

    /**
     * verify the Subject against the provided template and create a user in the XML backend.
     *
     * @param user Subject to create in the XML backend
     * @throws AuthenticationException if user already exists
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager
     */
    public Subject createUser(SubjectTemplate user, Organization organization) {
        Subject userCreated;
        if (organization != null) {
            //validate credentials of the SubjectTemplate
            organization.getSubjectTemplate().validateTemplate(user);
            userCreated = organization.getSubjectTemplate().toSubject(user, organization);
        } else {
            throw new IllegalArgumentException("organization is  null ");
        }

        try {
            if (!userAlreadyExists(userCreated)) {
                //persist the user in the corresponding datasource backend
                persistUser(userCreated);
            } else {
                throw new RegistrationException(" user already exists ");
            }
        } catch (AuthenticationException e) {
            throw new RegistrationException(e);
        }

        logger.debug(" user persisted \n");
        return userCreated;
    }

    /**
     * verify the Subject and create a user in the backend.
     *
     * @param user Subject to create in the backend
     * @return a Subject containing only the principals owned by the current application.
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager
     */
    public Subject createUser(Subject user, Organization organization) {
        Set missingCredentials = null;
        if (organization != null) {
            //we remove unknown credential and return missing credentials
            missingCredentials = organization.getSubjectTemplate().validateRequiredCredentialsFromUser(user);
        } else {
            throw new IllegalArgumentException(" organization is null ");
        }
        //we remove unknown principals
        user.getPrincipals(RolePrincipal.class).retainAll(localPrincipalsSet);
        if (missingCredentials.size() == 0) {
            persistUser(user);
        } else {
            throw new AuthenticationException(" the user cannot be created :some credentials are missing " + missingCredentials);
        }
        return user;
    }


    /* verify the Subject and create a user in the XML backend.
    * @param user Subject to create in the XML backend
    * @see net.sf.jguard.core.authentication.manager.AuthenticationManager#createUser(javax.security.auth.Subject)
    */

    public Organization createOrganization(OrganizationTemplate organizationCandidate) {
        OrganizationTemplate ot = this.getOrganizationTemplate();
        if (ot == null) {
            throw new IllegalStateException(" organizationTemplate is null");
        }
        return createOrganization(ot, organizationCandidate);
    }

    /**
     * verify the organization against the provided template and create an organizationin the XML backend.
     *
     * @param organizationCandidate
     * @param organizationTemplate
     * @throws AuthenticationException if user already exists
     */
    public Organization createOrganization(OrganizationTemplate organizationTemplate, OrganizationTemplate organizationCandidate) {
        if (organizationTemplate == null) {
            throw new IllegalStateException(" organizationTemplate is null ");
        }
        Organization organizationCreated = null;
        if (organizationCandidate != null) {
            //validate credentials of the organizationCandidate
            organizationTemplate.validateTemplate(organizationCandidate);
            organizationCreated = organizationTemplate.buildOrganization(organizationCandidate);
        } else {
            organizationCreated = organizationTemplate.toOrganization();
        }

        try {
            if (!organizationAlreadyExists(organizationCreated)) {
                //persist the user in the corresponding datasource backend
                persistOrganization(organizationCreated);
            } else {
                throw new RegistrationException(" organization already exists ");
            }
        } catch (AuthenticationException e) {
            throw new RegistrationException(e);
        }

        logger.debug(" organization persisted \n");
        return organizationCreated;
    }


    /**
     * create a Principal in the backend, <strong>only</strong> if it is not already present.
     *
     * @param principal Principal to create in the backend
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager
     */
    public void createPrincipal(Principal principal) {
        if (!localPrincipalsSet.contains(principal) && isRoleAndLocal(principal)) {
            localPrincipalsSet.add(principal);
            localPrincipals.put(principal.getName(), principal);
            persistPrincipal(principal);
        }
    }

    /**
     * persist user in the datasource backend.
     *
     * @param user
     */
    protected abstract void persistUser(Subject user);

    /**
     * persist role in the datasource backend.
     *
     * @param principal to persist
     */
    protected abstract void persistPrincipal(Principal principal);


    /**
     * persist role in the datasource backend.
     *
     * @param organization to persist
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    protected abstract void persistOrganization(Organization organization) throws AuthenticationException;


    /**
     * get a set of principals defined in the repository for all the applications.
     *
     * @return role's list.
     */
    public Set<Principal> getLocalPrincipals() {
        return new HashSet<Principal>(localPrincipalsSet);
    }

    /**
     * retrieve role from the principals set of the webapp.
     *
     * @param name
     * @return role found or null if not found
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager
     */
    public Principal getLocalPrincipal(String name) throws AuthenticationException {
        Principal principal = localPrincipals.get(name);
        if (principal instanceof RolePrincipal) {
            return new RolePrincipal(principal.getName(), (RolePrincipal) principal);
        }
        return null;
    }

    /**
     * indicate wether the user exists in the webapp or not.
     *
     * @param user we are looking for
     * @return true if registered in the webapp, false otherwise
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager#userAlreadyExists(javax.security.auth.Subject)
     */
    public boolean userAlreadyExists(Subject user) throws AuthenticationException {

        JGuardCredential identityCred = extractIdentityCredentialFromUser(user);

        Subject subject = findUser((String) identityCred.getValue());
        return subject != null;
    }

    /**
     * indicate wether the organization exists in the webapp or not.
     *
     * @param organization we are looking for
     * @return true if registered, false otherwise
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager#userAlreadyExists(javax.security.auth.Subject)
     */
    public boolean organizationAlreadyExists(Organization organization) throws AuthenticationException {
        Organization orga = findOrganization(organization.getName());
        return orga != null;
    }


    /**
     * verify whether or not the role exists in the webapp.
     *
     * @param role
     */
    public boolean hasPrincipal(Principal role) throws AuthenticationException {
        return localPrincipalsSet.contains(role);
    }

    /**
     * verify whether or not the role exists in the webapp.
     *
     * @param ppalName Principal's name
     */
    public boolean hasPrincipal(String ppalName) throws AuthenticationException {
        for (Principal aLocalPrincipalsSet : localPrincipalsSet) {
            if (aLocalPrincipalsSet.getName().equals(ppalName)) {
                return true;
            }
        }
        return false;
    }

    public void updateUser(JGuardCredential identityCred, Subject user) throws AuthenticationException {
        // remove non-persistant principals
        Set principals = user.getPrincipals();
        Set<UserPrincipal> userPrincipals = user.getPrincipals(UserPrincipal.class);
        for (UserPrincipal userPrincipal : userPrincipals) {
            principals.remove(userPrincipal);
        }

        updateUserImpl(identityCred, user);

        // add updated userPrincipal (only if was created previously)
        if (!userPrincipals.isEmpty()) {
            user.getPrincipals().add(new UserPrincipal(user));
        }
    }

    protected abstract void updateUserImpl(JGuardCredential identityCred, Subject user) throws AuthenticationException;


    /**
     * search the users which matches credentials criterions.
     *
     * @param privateCredentials
     * @param publicCredentials
     * @return users found
     */
    public abstract Set<Subject> findUsers(Collection<JGuardCredential> privateCredentials, Collection<JGuardCredential> publicCredentials) throws AuthenticationException;


    public abstract Set getUsers() throws AuthenticationException;


    public void importAuthenticationManager(AuthenticationManager authManager) {
        if (authManager.isEmpty()) {
            logger.warn(" authManager to import is empty ");
            return;
        }


        Set ppals;
        try {
            //set OrganizationTemplate
            setOrganizationTemplate(authManager.getOrganizationTemplate());

            //import global principals
            ppals = authManager.getAllPrincipalsSet();
            for (Object ppal1 : ppals) {
                Principal ppal = (Principal) ppal1;
                try {
                    createPrincipal(ppal);
                } catch (AuthenticationException e) {
                    logger.error(" principal cannot persisted : ", e);
                }
            }

        } catch (AuthenticationException e) {
            logger.error(" principals cannot be grabbed : ", e);
        }

        //import organizations
        Set organizationsSet;
        try {
            organizationsSet = authManager.getOrganizations();
            for (Object anOrganizationsSet : organizationsSet) {
                Organization orga = (Organization) anOrganizationsSet;

                createOrganization(orga);

            }


        } catch (AuthenticationException e) {
            logger.error(" principal cannot persisted : ", e);
        }


        //import users
        Set<Subject> usersSet;
        try {
            usersSet = authManager.getUsers();
            for (Object anUsersSet : usersSet) {
                Subject user = (Subject) anUsersSet;
                persistUser(user);
            }

        } catch (AuthenticationException e) {
            logger.error(" default subject template cannot be persisted : ", e);
        }

    }


    /**
     * extract credentials sought
     *
     * @param credentials Ids Sought
     * @param credentials
     * @return
     */
    protected Set<JGuardCredential> extractCredentials(Set credentialsIdSought, Set credentials) {
        Set<JGuardCredential> credentialsFromSubject = new HashSet<JGuardCredential>();
        for (Object credential : credentials) {
            JGuardCredential cred = (JGuardCredential) credential;
            String credId = cred.getName();
            for (Object aCredentialsIdSought : credentialsIdSought) {
                String idSought = (String) aCredentialsIdSought;
                if (idSought.equals(credId)) {
                    credentialsFromSubject.add(cred);
                }
            }
        }
        return credentialsFromSubject;
    }

    protected Set extractCredentialsFromSubject(Set credentialsSought, Subject user) {
        Set<JGuardCredential> credentialsFromSubject = new HashSet<JGuardCredential>();
        credentialsFromSubject.addAll(extractCredentials(credentialsSought, user.getPublicCredentials(JGuardCredential.class)));
        credentialsFromSubject.addAll(extractCredentials(credentialsSought, user.getPrivateCredentials(JGuardCredential.class)));
        return credentialsFromSubject;
    }

    protected JGuardCredential extractIdentityCredentialFromUser(Subject user) throws AuthenticationException {
        Set<String> creds = new HashSet<String>();
        creds.add(getCredentialId());
        Set credsFound = extractCredentialsFromSubject(creds, user);
        if (credsFound.size() > 1) {
            throw new IllegalArgumentException(" the user has got more than one identity argument ");
        } else if (credsFound.size() < 1) {
            throw new IllegalArgumentException(" the user has'nt got  one identity argument ");
        } else {
            return (JGuardCredential) credsFound.iterator().next();
        }
    }

    /**
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager#clonePrincipal(String roleName)
     */
    public Principal clonePrincipal(String roleName) throws AuthenticationException {
        Random rnd = new Random();
        String cloneName = roleName + rnd.nextInt(99999);

        return clonePrincipal(roleName, cloneName);
    }

    /**
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager#clonePrincipal(String roleName, String cloneName)
     */
    public Principal clonePrincipal(String roleName, String cloneName) throws AuthenticationException {
        Principal role = localPrincipals.get(roleName);
        Principal clone;
        if (role instanceof RolePrincipal) {
            RolePrincipal rp = (RolePrincipal) role;
            clone = new RolePrincipal(rp.getLocalName(), rp.getApplicationName(), rp.getOrganization());
        } else {
            clone = PrincipalUtils.getPrincipal(role.getClass().getName(), cloneName);
        }
        //persist the newly created clone
        createPrincipal(clone);

        return clone;
    }

    /**
     * change 'active' property on the specified role for a user.
     * this change cannot be done on 'guest' user, or if it remains only one 'active=true' role.
     *
     * @param subject
     * @param roleName
     * @param applicationName
     * @param active
     * @throws AuthenticationException
     */
    public void setActiveOnRolePrincipal(Subject subject, String roleName, String applicationName, boolean active) throws AuthenticationException {
        //guest users cannot change their 'guest' role.
        if (roleName.equals(GuestCallbacksProvider.GUEST)) {
            throw new AuthenticationException(GuestCallbacksProvider.GUEST + " 'active' property cannot be modified  ");
        }
        JGuardCredential identityCredential = extractIdentityCredentialFromUser(subject);
        if (!active && !checkMultipleActiveRoleExists(subject)) {
            throw new AuthenticationException("only one role is active from the same application. user cannot inactivate it ");
        }
        Principal principal = getRole(subject, roleName, applicationName);
        if (principal instanceof RolePrincipal) {
            RolePrincipal role = (RolePrincipal) principal;
            role.setActive(active);
            updateUser(identityCredential, subject);
        } else {
            logger.warn("active can only be applied to RolePrincipal");
        }
    }

    public Principal getRole(Subject subject, String roleName, String applicationName) throws AuthenticationException {
        if (roleName == null || roleName.equals("")) {
            throw new AuthenticationException("roleName is null or empty");
        }
        if (applicationName == null || applicationName.equals("")) {
            throw new AuthenticationException("applicationName is null or empty");
        }
        Set principals = subject.getPrincipals();
        Iterator it = principals.iterator();
        Principal principalFound = null;
        while (it.hasNext()) {
            Principal principal = (Principal) it.next();
            if (roleName.equals(principal.getName())) {
                principalFound = principal;
                break;
            }

        }
        if (principalFound == null) {
            throw new AuthenticationException("  role not found with name=" + roleName + " and applicationName=" + applicationName);
        }
        return principalFound;
    }

    /**
     * check that user owns multiple 'active' roles from the <u>same</u> application.
     *
     * @param subject
     * @return
     */
    private boolean checkMultipleActiveRoleExists(Subject subject) {
        Set principals = subject.getPrincipals();
        Iterator it = principals.iterator();
        int activeRoles = 0;
        while (it.hasNext()) {
            Principal principal = (Principal) it.next();

            if (principal instanceof RolePrincipal) {
                RolePrincipal rPrincipal = null;
                rPrincipal = (RolePrincipal) principal;
                if (rPrincipal.isActive() && this.applicationName.equals(rPrincipal.getApplicationName())) {
                    activeRoles++;
                }
            }

        }
        return activeRoles > 1;
    }

    /**
     * finds a user with a <b>public</b> Credential with name='login' and value= parameter of this method.
     *
     * @param login
     * @return Subject
     */
    public Subject findUser(String login) {
        Set<JGuardCredential> credentials = new HashSet<JGuardCredential>();
        Subject user = null;
        JGuardCredential jcred = new JGuardCredential(getCredentialId(), login);
        credentials.add(jcred);

        Collection usersFound = findUsers(new ArrayList<JGuardCredential>(), credentials);
        Iterator itUsers = usersFound.iterator();
        if (itUsers.hasNext()) {
            user = (Subject) itUsers.next();
        }

        return user;
    }

    public void updateRoleDefinition(Subject subject, String roleName, String applicationName, String definition) throws AuthenticationException {
        RolePrincipal ppal = (RolePrincipal) getRole(subject, roleName, applicationName);
        ppal.setDefinition(definition);
        JGuardCredential identity = SubjectUtils.getIdentityCredential(subject, this);
        updateUser(identity, subject);

    }

    public String getCredentialId() {
        return credentialId;
    }


    /**
     * @return a cloned version  of the OrganizationTemplate.
     */
    public OrganizationTemplate getOrganizationTemplate() {
        try {
            return (OrganizationTemplate) organizationTemplate.clone();
        } catch (CloneNotSupportedException ex) {
            throw new IllegalStateException("organizationtemplate cannot be cloned " + ex.getMessage(), ex);
        }
    }

    private Organization createOrganization(Organization orga) throws RegistrationException {
        return createOrganization(new OrganizationTemplate(orga));
    }

    /**
     * return true if the principal is an instance of a class or subclass
     * of RolePrincipal and if its applicationName is equals to the name
     * of the running application.
     *
     * @param principal
     * @return
     */
    protected boolean isRoleAndLocal(Principal principal) {
        if (applicationName == null) {
            throw new IllegalStateException(" applicationName is null and must be defined ");
        }
        if (isRole(principal)) {
            RolePrincipal role = (RolePrincipal) principal;
            if (applicationName.equals(role.getApplicationName())) {
                return true;
            }
        }
        return false;
    }

    protected boolean isRole(Principal principal) {
        return principal.getClass().isAssignableFrom(RolePrincipal.class);
    }

    public String getCredentialPassword() {
        return credentialPassword;
    }

}
