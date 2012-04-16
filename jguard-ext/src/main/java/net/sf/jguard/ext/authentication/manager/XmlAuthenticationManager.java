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

import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.manager.AbstractAuthenticationManager;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.authentication.manager.AuthenticationXmlStoreFileLocation;
import net.sf.jguard.core.authorization.permissions.RolePrincipal;
import net.sf.jguard.core.principals.Organization;
import net.sf.jguard.core.principals.OrganizationTemplate;
import net.sf.jguard.core.principals.SubjectTemplate;
import net.sf.jguard.core.util.XMLUtils;
import org.dom4j.*;
import org.dom4j.io.HTMLWriter;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.XMLWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.Subject;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.security.Principal;
import java.util.*;

/**
 * AuthenticationManager implementation which persists in an XML repository file.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
public class XmlAuthenticationManager extends AbstractAuthenticationManager implements AuthenticationManager {

    public static final String AUTHENTICATION = "authentication";
    private static final String PUBLIC_OPTIONAL_CREDENTIALS = "publicOptionalCredentials";
    private static final String PRIVATE_OPTIONAL_CREDENTIALS = "privateOptionalCredentials";
    private static final String PUBLIC_REQUIRED_CREDENTIALS = "publicRequiredCredentials";
    private static final String CRED_TEMPLATE_ID = "credTemplateId";
    private static final String PRIVATE_REQUIRED_CREDENTIALS = "privateRequiredCredentials";
    private static final String USER_TEMPLATE = "userTemplate";
    private static final String VALUE = "value";
    private static final String ID = "id";
    private static final String CREDENTIAL = "credential";
    private static final String CREDENTIALS = "credentials";
    private static final String PRINCIPAL_REF = "principalRef";
    private static final String PRINCIPALS_REF = "principalsRef";
    private static final String PUBLIC_CREDENTIALS = "publicCredentials";
    private static final String PRIVATE_CREDENTIALS = "privateCredentials";
    private static final String USER = "user";
    private static final String USERS = "users";
    private static final String APPLICATION_NAME = "applicationName";
    private static final String CLASS = "class";
    private static final String NAME = "name";
    private static final String ACTIVE = "active";
    private static final String DEFINITION = "definition";
    private static final String PRINCIPAL = "principal";
    private static final String PRINCIPALS = "principals";
    private static final String ORGANIZATIONS = "organizations";
    private static final String ORGANIZATION = "organization";
    private static final String ORGANIZATION_TEMPLATE = "organizationTemplate";
    private static final String ORGANIZATION_REF = "organizationRef";


    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(XmlAuthenticationManager.class.getName());
    private Document document = null;
    private Element root = null;
    private URL fileLocation = null;

    private static final String HTTP_JGUARD_SOURCEFORGE_NET_XSD_J_GUARD_USERS_PRINCIPALS_2_0_0_XSD = "http://jguard.sourceforge.net/xsd/jGuardUsersPrincipals_2.0.0.xsd";
    private static final String STRING_NAMESPACE_PREFIX = "j";


    //principals from multiple applications
    private Set<Principal> principalsSet;

    //link principals applicationName#name(as keys) and principals objects from multiple applications
    private Map<String, Principal> principals;
    private Set<Subject> users;


    private static final String J_GUARD_USERS_PRINCIPALS_2_2_0_XSD = "jGuardUsersPrincipals_2.0.0.xsd";
    private static final String TEMPLATE = "template";


    /**
     * initialise the DAO by reading the XML file, and converting it in objects.
     *
     * @param applicationName name of the application
     * @param fileLocation    location of the file storing users and roles
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager
     */
    @Inject
    public XmlAuthenticationManager(@ApplicationName String applicationName, @AuthenticationXmlStoreFileLocation URL fileLocation) {
        super(applicationName);

        this.applicationName = applicationName;


        this.fileLocation = fileLocation;

        if (fileLocation == null) {
            String message = " parameter '" + AUTHENTICATION_XML_FILE_LOCATION + "' which is null must be specified in the XmlLoginModule configuration ";
            logger.error(message);
            throw new IllegalArgumentException(message);
        }
        if (logger.isDebugEnabled()) {
            logger.debug("initAuthenticationDAO() - fileLocation=" + fileLocation);
        }
        URL schemaURL = Thread.currentThread().getContextClassLoader().getResource(J_GUARD_USERS_PRINCIPALS_2_2_0_XSD);

        document = XMLUtils.read(fileLocation, schemaURL);
        root = document.getRootElement();

        //initialize principals WITHOUT organization references (last step)
        Map<RolePrincipal, String> principalsAndOrganizationRefs = initPrincipals(root);

        super.organizationTemplate = getOrganizationTemplate(root);

        initOrganizations(root);

        resolvePrincipalsOrganizationRefs(principalsAndOrganizationRefs, organizations);
        users = initUsers(root);

    }


    /**
     * persist principal in the XML repository.
     *
     * @param principal to persist
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager
     */
    protected void persistPrincipal(Principal principal) throws AuthenticationException {
        Element prpals = root.element(XmlAuthenticationManager.PRINCIPALS);
        Element newPrincipal = prpals.addElement(XmlAuthenticationManager.PRINCIPAL);
        Element principalName = newPrincipal.addElement(XmlAuthenticationManager.NAME);
        principalName.setText(principal.getName());

        Element principalClass = newPrincipal.addElement(XmlAuthenticationManager.CLASS);
        principalClass.setText(principal.getClass().getName());

        Element appName = newPrincipal.addElement(XmlAuthenticationManager.APPLICATION_NAME);
        if (principal instanceof RolePrincipal) {
            RolePrincipal rp = (RolePrincipal) principal;
            principalName.setText(rp.getLocalName());
            appName.setText(rp.getApplicationName());
            Element organizationRef = newPrincipal.addElement(XmlAuthenticationManager.ORGANIZATION_REF);
            organizationRef.setText(rp.getOrganization().getName());
        }
        try {
            XMLUtils.write(fileLocation, document);
        } catch (IOException e) {
            logger.error(e.getMessage());
            throw new AuthenticationException(e.getMessage(), e);
        }
    }


    /**
     * update user's informations in the XML repository file.
     *
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager#updateUser(JGuardCredential, javax.security.auth.Subject)
     */
    protected void updateUserImpl(JGuardCredential identityCred, Subject user) throws AuthenticationException {
        logger.debug("update user - identityCred =" + identityCred);
        Subject userFound = findUser((String) identityCred.getValue());
        if (userFound != null) {
            deleteUser(userFound);
            persistUser(user);
        } else {
            logger.info("no user found for update with identity credential=" + identityCred);
        }
    }


    /**
     * remove user from users repository stored in memory.
     *
     * @param user to remove
     * @throws AuthenticationException
     */
    private void deleteUserFromMemory(Subject user) throws AuthenticationException {
        deleteUserFromMemory(extractIdentityCredentialFromUser(user));
    }

    /**
     * remove user from users repository stored in memory.
     *
     * @param identityCred 'identity' credential from the user to remove.
     * @throws AuthenticationException
     */
    private void deleteUserFromMemory(JGuardCredential identityCred) throws AuthenticationException {
        Iterator itUsers = users.iterator();
        while (itUsers.hasNext()) {
            Subject user = (Subject) itUsers.next();
            JGuardCredential credFromUser = extractIdentityCredentialFromUser(user);
            if (identityCred.equals(credFromUser)) {
                itUsers.remove();
                logger.debug("user with identityCred:" + identityCred.getName() + " =" + identityCred.getValue().toString() + " removed ");
                break;
            }
        }
    }

    /**
     * remove the user from the XML repository.
     *
     * @param user to remove
     * @throws AuthenticationException
     * @see net.sf.jguard.core.authentication.manager.AuthenticationManager#deleteUser(javax.security.auth.Subject)
     */
    public void deleteUser(Subject user) throws AuthenticationException {
        if (user != null) {
            deleteUserFromMemory(user);

            Element userElement = findUser(user);
            if (userElement != null) {
                root.element(XmlAuthenticationManager.USERS).elements(XmlAuthenticationManager.USER).remove(userElement);
                try {
                    XMLUtils.write(fileLocation, document);
                } catch (IOException e) {
                    logger.error("removeUser(Subject)", e);
                    throw new AuthenticationException(e.getMessage(), e);
                }

            }
        }
    }

    private Element getOrganization(String organizationId) throws InvalidXPathException {

        String xpath = getXpathSearchStringForOrganization(organizationId);
        return getElement(xpath);
    }

    private Element getElement(String xpath) {
        XPath xp2 = DocumentHelper.createXPath(xpath);
        Map<String, String> uris = new HashMap<String, String>();
        uris.put(STRING_NAMESPACE_PREFIX, HTTP_JGUARD_SOURCEFORGE_NET_XSD_J_GUARD_USERS_PRINCIPALS_2_0_0_XSD);
        xp2.setNamespaceURIs(uris);

        return (Element) xp2.selectSingleNode(root);
    }

    /**
     * find the DOM4J Element corresponding to this Subject, null otherwise.
     *
     * @param user subject we are looking for in the XML repository file.
     * @return Element corresponding to the found user, null if not found.
     * @throws AuthenticationException
     */
    private Element findUser(Subject user) throws AuthenticationException {

        JGuardCredential identityCred = extractIdentityCredentialFromUser(user);

        return findUser(identityCred);
    }


    /**
     * return the DOM4J element which match with the identityCredential provided.
     *
     * @param identityCred
     * @return null if no user is found, an Element if user found
     */
    private Element findUser(JGuardCredential identityCred) {
        logger.debug("try to find user with identityCredential=" + identityCred);
        Element usersElement = root.element(XmlAuthenticationManager.USERS);
        String xpathforUser = getUserXpath(identityCred);
        Element user = getElement(xpathforUser);
        if (user == null) {
            //no user has been found
            logger.debug("no user has been found");
        }
        return user;
    }

    private String getUserXpath(JGuardCredential identityCred) {
        return "/j:authentication/j:users/j:user/j:privateCredentials/j:credential[@id='" + identityCred.getName() + "' and @value='" + identityCred.getValue().toString() + "']/../..";
    }

    private Set getCredentialsSet(Element credentialsElement) {
        List credentialsElements = credentialsElement.elements(XmlAuthenticationManager.CREDENTIAL);
        Iterator itCred = credentialsElements.iterator();
        Set<JGuardCredential> credentials = new HashSet<JGuardCredential>();
        while (itCred.hasNext()) {
            Element credentialElement = (Element) itCred.next();

            String id = credentialElement.attribute(XmlAuthenticationManager.ID).getStringValue();
            String value = credentialElement.attribute(XmlAuthenticationManager.VALUE).getStringValue();
            JGuardCredential credential = new JGuardCredential(id, value);
            credentials.add(credential);
        }
        return credentials;
    }

    private Organization getOrganization(Element organizationElement) {
        if (organizationElement == null) {
            throw new IllegalArgumentException("organizationElement in argument is null");
        }
        Organization organization = new Organization();

        Set<RolePrincipal> ppals = getPrincipalsReference(organizationElement);
        organization.setPrincipals(ppals);
        Element userTemplateElement = organizationElement.element(XmlAuthenticationManager.USER_TEMPLATE);
        SubjectTemplate subjTemplate = buildSubjectTemplateFromElement(userTemplateElement);
        organization.setSubjectTemplate(subjTemplate);

        Element credentialsElement = organizationElement.element(XmlAuthenticationManager.CREDENTIALS);
        Set credentials = getCredentialsSet(credentialsElement);
        organization.setCredentials(credentials);


        return organization;
    }

    private Organization getOrganizationPrincipal(Element userElement) {
        String organizationName = userElement.element(XmlAuthenticationManager.ORGANIZATION_REF).getStringValue();
        for (Organization organization : organizations) {
            if (organizationName.equals(organization.getName())) {
                return organization;
            }
        }
        logger.error(" organization with name" + organizationName + " have not been found");
        return null;
    }

    /**
     * @param root DOM4J Element
     * @return OrganizationTemplate parsed by this method
     */
    private OrganizationTemplate getOrganizationTemplate(Element root) {
        Element organizationsElement = root.element(XmlAuthenticationManager.ORGANIZATIONS);
        Element organizationTemplateElement = organizationsElement.element(XmlAuthenticationManager.ORGANIZATION_TEMPLATE);
        OrganizationTemplate template = new OrganizationTemplate();

        Element requiredCredentialsElement = organizationTemplateElement.element(XmlAuthenticationManager.CREDENTIALS);
        List reqCredsElement = requiredCredentialsElement.elements(XmlAuthenticationManager.CRED_TEMPLATE_ID);
        Set reqCreds = getJGuardCredentialList(reqCredsElement);
        template.setCredentials(reqCreds);

        Set orgaTemplatePrincipals = getPrincipalsReference(organizationTemplateElement);
        template.setPrincipals(orgaTemplatePrincipals);
        SubjectTemplate subjTemplate = getSubjectTemplate(organizationTemplateElement);

        template.setSubjectTemplate(subjTemplate);
        return template;
    }

    /**
     * parse the DOM4J element and return the set of <i>RolePrincipal</i> referenced in
     * the element.
     *
     * @param parentElement containing the <i>principalsRef</i> DOM4J Element.
     * @return Set of RolePrincipal
     */
    private Set<RolePrincipal> getPrincipalsReference(Element parentElement) {

        Set<RolePrincipal> userPrincipals = new HashSet<RolePrincipal>();

        Element principalsRefElement = parentElement.element(XmlAuthenticationManager.PRINCIPALS_REF);
        List<Element> userPrincipalsRefElement = principalsRefElement.elements(XmlAuthenticationManager.PRINCIPAL_REF);
        for (Element principalElement : userPrincipalsRefElement) {
            String principalName = principalElement.attributeValue(XmlAuthenticationManager.NAME);
            String principalApplicationName = principalElement.attributeValue(XmlAuthenticationManager.APPLICATION_NAME);
            //if the applicationName is not set, the current applicationName is implied
            if (principalApplicationName == null) {
                principalApplicationName = super.applicationName;
            }
            String definition = principalElement.attributeValue(XmlAuthenticationManager.DEFINITION);
            String active = principalElement.attributeValue(XmlAuthenticationManager.ACTIVE);


            RolePrincipal principal = (RolePrincipal) principals.get(RolePrincipal.getName(principalName, applicationName));
            if (principal == null) {
                continue;
            }

            principal.setDefinition(definition);
            if ("true".equalsIgnoreCase(active)) {
                principal.setActive(true);
            } else {
                principal.setActive(false);
            }
            userPrincipals.add(principal);

        }
        return userPrincipals;
    }

    private String getXpathSearchStringForOrganization(String organizationId) {
        return "/j:authentication/j:organizations/j:organization/j:credentials/j:credential[@id='id' and @value='" + organizationId + "']/../..";
    }

    private void initOrganizations(Element root) {
        Element organizationsElement = root.element(XmlAuthenticationManager.ORGANIZATIONS);
        List organizationsList = organizationsElement.elements(XmlAuthenticationManager.ORGANIZATION);
        for (Object anOrganizationsList : organizationsList) {
            Element organizationElement = (Element) anOrganizationsList;
            Organization organization = getOrganization(organizationElement);
            organizations.add(organization);
        }

    }

    /**
     * initialize principals.
     *
     * @param root dom4j element
     * @return
     */
    private Map<RolePrincipal, String> initPrincipals(Element root) {
        Element principalsElement = root.element(XmlAuthenticationManager.PRINCIPALS);
        List<Element> principalsList = principalsElement.elements(XmlAuthenticationManager.PRINCIPAL);
        principals = new HashMap<String, Principal>();
        principalsSet = new HashSet<Principal>();
        Iterator<Element> itPrincipalsList = principalsList.iterator();
        Map<RolePrincipal, String> principalsAndOrganizationRefs = new HashMap<RolePrincipal, String>();
        while (itPrincipalsList.hasNext()) {
            Element principalElement = itPrincipalsList.next();
            String principalClass = principalElement.element(XmlAuthenticationManager.CLASS).getStringValue();
            if (!RolePrincipal.class.getName().equals(principalClass)) {
                throw new IllegalArgumentException("class=+" + principalClass + "is unsupported ; only class=" + RolePrincipal.class.getName() + " is supported");
            }
            Element applicationNameElement = principalElement.element(XmlAuthenticationManager.APPLICATION_NAME);


            Element organizationRefElement = principalElement.element(XmlAuthenticationManager.ORGANIZATION_REF);
            String organizationRefId = organizationRefElement.getStringValue();
            RolePrincipal principal = new RolePrincipal(principalElement.element(XmlAuthenticationManager.NAME).getStringValue(), applicationNameElement.getStringValue());

            principalsAndOrganizationRefs.put(principal, organizationRefId);
            principals.put(principal.getName(), principal);
            principalsSet.add(principal);
            if (principal.getApplicationName().equals(applicationName)) {
                localPrincipalsSet.add(principal);
                localPrincipals.put(principal.getName(), principal);
            }
        }
        if (localPrincipalsSet.isEmpty()) {
            throw new IllegalStateException("no principals are granted to the current application=" + getApplicationName());
        }
        return principalsAndOrganizationRefs;

    }

    /**
     * initialize users.
     *
     * @param root dom4j element
     * @return users Set
     */
    private Set<Subject> initUsers(Element root) {
        users = new HashSet<Subject>();
        Element usersElement = root.element(XmlAuthenticationManager.USERS);
        List usersList = usersElement.elements(XmlAuthenticationManager.USER);

        for (Object anUsersList : usersList) {
            Element userElement = (Element) anUsersList;

            Set privateCredentials;

            Element privateCredentialsElement = userElement.element(XmlAuthenticationManager.PRIVATE_CREDENTIALS);
            privateCredentials = getCredentialsSet(privateCredentialsElement);

            Set publicCredentials;
            Element publicCredentialsElement = userElement.element(XmlAuthenticationManager.PUBLIC_CREDENTIALS);
            publicCredentials = getCredentialsSet(publicCredentialsElement);
            Set userPrincipals = getPrincipalsReference(userElement);
            Organization organization = getOrganizationPrincipal(userElement);
            //set of RolePrincipal granted to the organization 
            Set organizationPrincipals = organization.getPrincipals();
            //we check that RolePrincipals granted to the user are a subset of 
            //RolePrincipals granted to the organization: we remove Roleprincipals
            //not granted to the organization
            userPrincipals.retainAll(new HashSet(organizationPrincipals));

            //we add the organization Principal to the user to be reach in contextual permissions
            userPrincipals.add(organization);

            //subject is not in read-only mode
            Subject user = new Subject(false, userPrincipals, publicCredentials, privateCredentials);
            if (userPrincipals.size() <= 1) {
                JGuardCredential cred = getIdentityCredential(user);
                logger.warn(" user " + cred.getName() + "=" + cred.getValue() + " hasn't got any RolePrincipals granted (no roles owned by his organization is granted to him) ");
            }
            users.add(user);
        }

        return users;
    }

    /**
     * construct from configuration file the subjectTemplate.
     *
     * @return Subject template built
     */
    public SubjectTemplate getSubjectTemplate(Element organizationNode) {

        Element subjectTemplateElement = organizationNode.element(XmlAuthenticationManager.USER_TEMPLATE);
        return buildSubjectTemplateFromElement(subjectTemplateElement);
    }


    private SubjectTemplate buildSubjectTemplateFromElement(Element userTemplate) {
        Element privateRequiredCredentials = userTemplate.element(XmlAuthenticationManager.PRIVATE_REQUIRED_CREDENTIALS);
        List privReqCreds = privateRequiredCredentials.elements(XmlAuthenticationManager.CRED_TEMPLATE_ID);
        Set privReqCreds2 = getJGuardCredentialList(privReqCreds);
        Element publicRequiredCredentials = userTemplate.element(XmlAuthenticationManager.PUBLIC_REQUIRED_CREDENTIALS);
        List pubReqCreds = publicRequiredCredentials.elements(XmlAuthenticationManager.CRED_TEMPLATE_ID);
        Set pubReqCreds2 = getJGuardCredentialList(pubReqCreds);
        Element privateOptionalCredentials = userTemplate.element(XmlAuthenticationManager.PRIVATE_OPTIONAL_CREDENTIALS);
        List privOptCreds = privateOptionalCredentials.elements(XmlAuthenticationManager.CRED_TEMPLATE_ID);
        Set privOptCreds2 = getJGuardCredentialList(privOptCreds);
        Element publicOptionalCredentials = userTemplate.element(XmlAuthenticationManager.PUBLIC_OPTIONAL_CREDENTIALS);
        List pubOptCreds = publicOptionalCredentials.elements(XmlAuthenticationManager.CRED_TEMPLATE_ID);
        Set pubOptCreds2 = getJGuardCredentialList(pubOptCreds);
        SubjectTemplate st = new SubjectTemplate();
        st.setPrivateRequiredCredentials(privReqCreds2);
        st.setPublicRequiredCredentials(pubReqCreds2);
        st.setPrivateOptionalCredentials(privOptCreds2);
        st.setPublicOptionalCredentials(pubOptCreds2);

        List principalElements = userTemplate.element(XmlAuthenticationManager.PRINCIPALS_REF).elements(XmlAuthenticationManager.PRINCIPAL_REF);
        Set genPpals = getPrincipals(principalElements);
        st.setPrincipals(genPpals);

        return st;
    }


    /**
     * return a Set of Principals referenced in a <i>principalsRef<i/>
     * element.
     *
     * @param principalElements
     * @return
     */
    private Set getPrincipals(List principalElements) {
        Set ppals = new HashSet();
        for (Object principalElement : principalElements) {
            Element ppalElement = (Element) principalElement;
            Principal ppal = principals.get(ppalElement.attribute(APPLICATION_NAME).getData() + "#" + ppalElement.attribute(NAME).getData());
            if (ppal != null) {
                ppals.add(ppal);
            }
        }

        return ppals;
    }

    /**
     * transform a list of DOM4J elements into a Set of JGuardCredentials.
     *
     * @param credTemplateIdElements list of DOM4J elements
     * @return Set of jGuardCredentials
     */
    private Set<JGuardCredential> getJGuardCredentialList(List credTemplateIdElements) {
        Iterator it = credTemplateIdElements.iterator();
        Set<JGuardCredential> jguardCredlist = new HashSet<JGuardCredential>();
        while (it.hasNext()) {
            Element credElement = (Element) it.next();
            JGuardCredential jcred = null;
            String id = credElement.getText();
            if (id.equals(ID)) {
                jcred = new JGuardCredential(id, TEMPLATE);
            } else {
                jcred = new JGuardCredential(id, "");
            }
            jguardCredlist.add(jcred);
        }
        return jguardCredlist;
    }

    /**
     * persist user into the XML repository file.
     *
     * @param user
     * @throws AuthenticationException
     */
    protected void persistUser(Subject user) throws AuthenticationException {
        Element xmlUsers = root.element(XmlAuthenticationManager.USERS);
        Element newUser = xmlUsers.addElement(XmlAuthenticationManager.USER);
        Element privateCredentials = newUser.addElement(XmlAuthenticationManager.PRIVATE_CREDENTIALS);
        Set privCredentialsSet = user.getPrivateCredentials(JGuardCredential.class);
        persistCredentialsSet(privCredentialsSet, privateCredentials);

        Element publicCredentials = newUser.addElement(XmlAuthenticationManager.PUBLIC_CREDENTIALS);
        Set pubCredentials = user.getPublicCredentials(JGuardCredential.class);
        persistCredentialsSet(pubCredentials, publicCredentials);

        Element ppals = newUser.addElement(XmlAuthenticationManager.PRINCIPALS_REF);
        Set prpals = user.getPrincipals();
        persistPrincipalRefs(prpals, ppals);

        Set organizations = user.getPrincipals(Organization.class);
        if (organizations.size() != 1) {
            throw new IllegalArgumentException("user" + user + "hasn't got one Organization but " + organizations.size() + " organizations ");
        }
        Organization orga = (Organization) organizations.iterator().next();
        Element organizationRef = newUser.addElement(XmlAuthenticationManager.ORGANIZATION_REF);
        organizationRef.setText(orga.getName());

        try {
            XMLUtils.write(fileLocation, document);
            //add the user to the in-memory users repository
            this.users.add(user);
        } catch (IOException e) {
            logger.error("persistUser(Subject)", e);
            throw new AuthenticationException(e.getMessage(), e);
        }
    }

    private void persistCredentialTemplates(Set credentials, Element subjectTemplateElement, String credentialConstant) {
        Element credentialsElement = subjectTemplateElement.addElement(credentialConstant);
        if (credentialsElement == null) {
            logger.debug("credentialTemplateID element in XML " + credentialConstant + " is null");
            return;
        }
        if (credentials == null || credentials.size() == 0) {
            logger.debug("credentials" + credentialConstant + " in Object is null or empty");
            return;
        }
        for (Object credential : credentials) {
            JGuardCredential cred = (JGuardCredential) credential;
            Element cred1 = credentialsElement.addElement(XmlAuthenticationManager.CRED_TEMPLATE_ID);
            cred1.setText(cred.getName());
        }
    }

    private void persistOrganization(Organization organization, Element organizationElement) throws AuthenticationException {
        SubjectTemplate template = organization.getSubjectTemplate();
        if (template == null) {
            throw new IllegalArgumentException("SubejctTemplate is null into Organization " + organization);
        }
        persistSubjectTemplate(organizationElement, template);

        Element newCredentialsElement = organizationElement.addElement(XmlAuthenticationManager.CREDENTIALS);

        Set credentials = organization.getCredentials();
        for (Object credential : credentials) {
            JGuardCredential cred = (JGuardCredential) credential;
            Element credElement = newCredentialsElement.addElement(XmlAuthenticationManager.CREDENTIAL);
            credElement.addAttribute(XmlAuthenticationManager.ID, cred.getName());
            credElement.addAttribute(XmlAuthenticationManager.VALUE, cred.getValue().toString());
        }

        Element principalsRefElement = organizationElement.addElement(XmlAuthenticationManager.PRINCIPALS_REF);
        Set orgaPrincipals = organization.getPrincipals();
        for (Object orgaPrincipal : orgaPrincipals) {
            RolePrincipal ppal = (RolePrincipal) orgaPrincipal;
            Element principalRefElement = principalsRefElement.addElement(XmlAuthenticationManager.PRINCIPAL_REF);
            principalRefElement.addAttribute(XmlAuthenticationManager.NAME, ppal.getLocalName());
            principalRefElement.addAttribute(XmlAuthenticationManager.APPLICATION_NAME, ppal.getApplicationName());
            principalRefElement.addAttribute(XmlAuthenticationManager.DEFINITION, ppal.getDefinition());
            principalRefElement.addAttribute(XmlAuthenticationManager.ACTIVE, ppal.isActive() ? "true" : "false");
        }
        try {
            XMLUtils.write(fileLocation, document);
        } catch (IOException e) {
            logger.error(e.getMessage());
            throw new AuthenticationException(e.getMessage(), e);
        }
    }

    /**
     * persist principals into the XML repository file.
     *
     * @param principals
     * @param ppals      DOM4J Element
     */
    private void persistPrincipalRefs(Set principals, Element ppals) {

        for (Object principal1 : principals) {
            Principal ppal = (Principal) principal1;
            if (ppal instanceof RolePrincipal) {
                RolePrincipal jppal = (RolePrincipal) ppal;
                Element principal = ppals.addElement(XmlAuthenticationManager.PRINCIPAL_REF);
                principal.addAttribute(XmlAuthenticationManager.NAME, jppal.getLocalName());
                principal.addAttribute(XmlAuthenticationManager.APPLICATION_NAME, jppal.getApplicationName());
                principal.addAttribute(XmlAuthenticationManager.DEFINITION, jppal.getDefinition());
                principal.addAttribute(XmlAuthenticationManager.ACTIVE, jppal.isActive() ? "true" : "false");
            }
        }

    }


    /**
     * persist a jGuardCredential set into the XML subset corresponding to the
     * credentialsSetElement.
     *
     * @param credentials
     * @param credentialsSetElement
     */
    private void persistCredentialsSet(Set credentials, Element credentialsSetElement) {
        for (Object credential1 : credentials) {
            JGuardCredential jcred2 = (JGuardCredential) credential1;
            Element credential = credentialsSetElement.addElement(XmlAuthenticationManager.CREDENTIAL);
            credential.addAttribute(XmlAuthenticationManager.ID, jcred2.getName());
            credential.addAttribute(XmlAuthenticationManager.VALUE, jcred2.getValue().toString());

        }

    }


    /**
     * define and persist the SubjectTemplate for registration.
     *
     * @param organizationElement
     * @param template
     */
    public void persistSubjectTemplate(Element organizationElement, SubjectTemplate template) {
        Element subjectTemplateElement = organizationElement.addElement(XmlAuthenticationManager.USER_TEMPLATE);
        if (subjectTemplateElement == null) {
            throw new IllegalArgumentException(" subjectTemplate is not present into organizationElement " + organizationElement.getName());
        }

        if (template == null) {
            throw new IllegalArgumentException(" SubjectTemplate is null");
        }
        persistCredentialTemplates(template.getPrivateRequiredCredentials(), subjectTemplateElement, XmlAuthenticationManager.PRIVATE_REQUIRED_CREDENTIALS);
        persistCredentialTemplates(template.getPublicRequiredCredentials(), subjectTemplateElement, XmlAuthenticationManager.PUBLIC_REQUIRED_CREDENTIALS);
        persistCredentialTemplates(template.getPrivateOptionalCredentials(), subjectTemplateElement, XmlAuthenticationManager.PRIVATE_OPTIONAL_CREDENTIALS);
        persistCredentialTemplates(template.getPublicOptionalCredentials(), subjectTemplateElement, XmlAuthenticationManager.PUBLIC_OPTIONAL_CREDENTIALS);
        Element principalsRefElement = subjectTemplateElement.addElement(XmlAuthenticationManager.PRINCIPALS_REF);
        persistPrincipalRefs(template.getPrincipals(), principalsRefElement);
    }

    /**
     * @return <i>true</i> if there is no principals and no permissions.
     *         <i>false</i> otherwise.
     */
    public boolean isEmpty() {
        Element principalsElement = root.element(XmlAuthenticationManager.PRINCIPALS);
        List principalsList = principalsElement.elements(XmlAuthenticationManager.PRINCIPAL);


        Element usersElement = root.element(XmlAuthenticationManager.USERS);
        List usersList = usersElement.elements(XmlAuthenticationManager.USER);

        return !(!principalsList.isEmpty() && !usersList.isEmpty());

    }


    public Set<Principal> getAllPrincipalsSet() {
        return new HashSet<Principal>(principalsSet);
    }


    /**
     * search the users which matches credentials criterions.
     *
     * @param privateCredentials
     * @param publicCredentials
     * @return users found
     */
    public Set<Subject> findUsers(Collection privateCredentials, Collection publicCredentials) {
        Set<Subject> usersFound = new HashSet<Subject>();
        for (Subject user : users) {
            Iterator privItCred = privateCredentials.iterator();
            boolean userFound = true;
            while (privItCred.hasNext()) {
                JGuardCredential jcred = (JGuardCredential) privItCred.next();
                if (user.getPrivateCredentials().contains(jcred)) {
                    continue;
                } else {
                    userFound = false;
                }
            }
            if (!userFound) {
                //Subject in evaluation does not match private credentials constraints
                //we skip it and evaluate the next subject
                continue;
            }

            for (Object publicCredential : publicCredentials) {
                JGuardCredential jcred = (JGuardCredential) publicCredential;
                if (user.getPublicCredentials().contains(jcred)) {
                    continue;
                } else {
                    userFound = false;
                }
            }

            if (userFound) {
                //Subject in evaluation matches private and public credentials constraints
                //we copy the object to prevent external modifications.
                //jguardCredential is immutable, others objects need to be refactored to be immutable in the future 
                usersFound.add(new Subject(false, user.getPrincipals(), user.getPublicCredentials(), user.getPrivateCredentials()));
            }
        }
        return usersFound;
    }

    public Set<Subject> getUsers() {
        return users;
    }


    public void updatePrincipal(String oldPrincipalName, Principal principal) {
        Principal oldPal = principals.remove(oldPrincipalName);
        if (oldPal == null) {
            logger.warn(" principal " + oldPrincipalName + " cannot be updated because it does not exists ");
            return;
        }
        principalsSet.remove(oldPal);
        principals.put(principal.getName(), principal);
        principalsSet.add(principal);

        if (isRoleAndLocal(oldPal) && localPrincipalsSet.contains(oldPal)) {
            localPrincipalsSet.remove(oldPal);
            localPrincipals.put(principal.getName(), principal);
            localPrincipalsSet.add(principal);
        }
        try {
            XMLUtils.write(fileLocation, document);
        } catch (IOException e) {
            logger.error("updateRole(String, RolePrincipal)", e);
        }

    }


    public boolean deletePrincipal(Principal principal) throws AuthenticationException {
        Principal ppalReference = principals.remove(principal.getName());
        if (ppalReference == null) {
            return false;
        }
        principalsSet.remove(ppalReference);

        if (isRoleAndLocal(principal) && localPrincipalsSet.contains(principal)) {
            localPrincipalsSet.remove(principal);
            localPrincipals.remove(principal);
        }
        Element principalsElement = root.element("principals");
        Element principalElement = (Element) principalsElement.selectSingleNode("//principal[name='" + principal.getName() + "']");
        principalsElement.remove(principalElement);
        if (ppalReference.getClass().equals(RolePrincipal.class)) {
            //delete all the references of this principal
            XMLUtils.deletePrincipalRefs(root, (RolePrincipal) ppalReference);
        }
        try {
            XMLUtils.write(fileLocation, document);
        } catch (IOException e) {
            logger.error("deletePrincipal(String)", e);
            throw new AuthenticationException(e.getMessage(), e);
        }
        return true;

    }


    public String exportAsXMLString() {
        return document.asXML();
    }

    public void writeAsXML(OutputStream outputStream, String encodingScheme) throws IOException {
        OutputFormat outformat = OutputFormat.createPrettyPrint();
        outformat.setEncoding(encodingScheme);
        XMLWriter writer = new XMLWriter(outputStream, outformat);
        writer.write(this.document);
        writer.flush();
    }


    public void writeAsHTML(OutputStream outputStream) throws IOException {
        HTMLWriter writer = new HTMLWriter(outputStream, OutputFormat.createPrettyPrint());
        writer.write(this.document);
        writer.flush();
    }


    public void exportAsXMLFile(String fileName) throws IOException {
        FileWriter fileWriter = null;
        try {
            fileWriter = new FileWriter(fileName);
            XMLWriter xmlWriter = new XMLWriter(fileWriter, OutputFormat.createPrettyPrint());
            xmlWriter.write(document);
            xmlWriter.close();
        } finally {
            if (fileWriter != null) {
                fileWriter.close();
            }
        }

    }


    public void deleteOrganization(Organization organisation) {
        String credId = organisation.getName();
        Element organizationElement = getOrganization(credId);
        root.remove(organizationElement);
    }

    public void updateOrganization(String organizationId, Organization organization) throws AuthenticationException {
        Element organizationElement = getOrganization(organizationId);
        if (organizationElement == null) {
            throw new IllegalArgumentException("organization cannot be updated : it doesn't exist ");
        }

        //remove userTemplate
        Element userTemplate = organizationElement.element(XmlAuthenticationManager.USER_TEMPLATE);
        if (userTemplate != null) {
            organizationElement.remove(userTemplate);
        }

        //remove credentilasElement
        Element credentialsElement = organizationElement.element(XmlAuthenticationManager.CREDENTIALS);
        organizationElement.remove(credentialsElement);

        Element oldPrincipalsRefElement = organizationElement.element(XmlAuthenticationManager.PRINCIPALS_REF);
        organizationElement.remove(oldPrincipalsRefElement);
        persistOrganization(organization, organizationElement);
    }


    public Organization findOrganization(String organizationId) {

        Element organizationFound = getOrganization(organizationId);

        if (organizationFound == null) {
            return null;
        }
        return getOrganization(organizationFound);

    }

    protected void persistOrganization(Organization organization) throws AuthenticationException {
        String id = organization.getName();
        String xpath = getXpathSearchStringForOrganization(id);
        logger.debug("id for organization =" + id);
        logger.debug("xpath for organization =" + xpath);
        Element organizationElement = root.element(xpath);
        if (organizationElement == null) {
            Element organizationsElement = root.element(ORGANIZATIONS);
            organizationElement = organizationsElement.addElement(ORGANIZATION);
        }
        persistOrganization(organization, organizationElement);
    }

    public Set<Organization> getOrganizations() throws AuthenticationException {
        return new HashSet<Organization>(organizations);
    }

    private void resolvePrincipalsOrganizationRefs(Map<RolePrincipal, String> principalsAndOwners, Set<Organization> organizations) {
        for (Map.Entry<RolePrincipal, String> entry : principalsAndOwners.entrySet()) {
            RolePrincipal principal = entry.getKey();
            String organizationId = entry.getValue();
            Organization orgaFound = findOrganization(organizations, organizationId);
            principal.setOrganization(orgaFound);
        }
    }

    public Collection findOrganizations(Collection credentials) throws AuthenticationException {
        Set<Organization> organizationsFound = new HashSet<Organization>();
        for (Organization organization : organizations) {
            Iterator itCred = credentials.iterator();
            boolean organizationFound = true;
            while (itCred.hasNext()) {
                JGuardCredential jcred = (JGuardCredential) itCred.next();
                if (organization.getCredentials().contains(jcred)) {
                    continue;
                } else {
                    organizationFound = false;
                }
            }

            if (organizationFound) {
                organizationsFound.add(organization);
            }
        }
        return organizationsFound;
    }

    public void setOrganizationTemplate(OrganizationTemplate organizationTemplate) throws AuthenticationException {
        Element organizationsElement = root.element(XmlAuthenticationManager.ORGANIZATIONS);
        Element organizationTemplateElement = organizationsElement.element(XmlAuthenticationManager.ORGANIZATION_TEMPLATE);

        Element requiredCredentialsElement = organizationTemplateElement.element(XmlAuthenticationManager.CREDENTIALS);

        List reqCredsElement = requiredCredentialsElement.elements(XmlAuthenticationManager.CRED_TEMPLATE_ID);
        for (Object aReqCredsElement : reqCredsElement) {
            Element elt = (Element) aReqCredsElement;
            requiredCredentialsElement.remove(elt);
        }

        Set creds = organizationTemplate.getCredentials();
        for (Object cred1 : creds) {
            JGuardCredential cred = (JGuardCredential) cred1;
            String name = cred.getName();
            Element credTemplateId = requiredCredentialsElement.addElement(XmlAuthenticationManager.CRED_TEMPLATE_ID);
            credTemplateId.setText(name);
        }

        persistPrincipalRefs(organizationTemplate.getPrincipals(), organizationTemplateElement);
        persistSubjectTemplate(organizationTemplateElement, organizationTemplate.getSubjectTemplate());


    }


} 
