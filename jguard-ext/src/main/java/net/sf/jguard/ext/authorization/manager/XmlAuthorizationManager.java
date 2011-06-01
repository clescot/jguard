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
package net.sf.jguard.ext.authorization.manager;

import javax.inject.Inject;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authorization.manager.AuthorizationManager;
import net.sf.jguard.core.authorization.manager.AuthorizationManagerException;
import net.sf.jguard.core.authorization.manager.AuthorizationManagerOptions;
import net.sf.jguard.core.authorization.manager.JGuardAuthorizationManagerMarkups;
import net.sf.jguard.core.authorization.permissions.PermissionUtils;
import net.sf.jguard.core.principals.PrincipalUtils;
import net.sf.jguard.core.principals.RolePrincipal;
import net.sf.jguard.core.util.XMLUtils;
import org.dom4j.*;
import org.dom4j.io.HTMLWriter;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.XMLWriter;
import org.dom4j.util.UserDataAttribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Permission;
import java.security.Principal;
import java.util.*;


/**
 * AuthorizationManager implementation which enable Permission Management with an XML backend.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @author <a href="mailto:vinipitta@users.sourceforge.net">Vinicius Pitta Lima de Araujo</a>
 */
public class XmlAuthorizationManager extends AbstractAuthorizationManager implements AuthorizationManager {
    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(XmlAuthorizationManager.class.getName());
    private static final String NO_PERMISSIONS_ARE_BUILT_FROM_XML_FILE = "no permissions are built from xml file";

    private Element root;
    private Document document = null;
    private String fileLocation;
    private static final String J_GUARD_PRINCIPALS_PERMISSIONS_2_00_XSD = "jGuardPrincipalsPermissions_2.0.0.xsd";
    private static final String NAME = "name";
    private static final String CLASS = "class";
    private static final String PERMISSIONS = "permissions";
    private static final String PERMISSION = "permission";
    private static final String ACTIONS = "actions";
    private static final String FILE_LOCATION = "fileLocation";
    private static final String ACTION = "action";
    private static final String PRINCIPALS = "principals";
    private static final String PRINCIPAL = "principal";
    private static final String PERMISSIONS_REF = "permissionsRef";
    private static final String PERMISSION_REF = "permissionRef";
    private static final String DOMAIN_REF = "domainRef";
    private static final String DESCENDANTS = "descendants";
    private static final String PRINCIPAL_REF = "principalRef";
    private static final String HTTP_JGUARD_SOURCEFORGE_NET_XSD_J_GUARD_PRINCIPALS_PERMISSIONS_2_0_0 = "http://jguard.sourceforge.net/xsd/jGuardPrincipalsPermissions_2.0.0";
    private static final String STRING_NAMESPACE_PREFIX = "j";
    private static final String XPATH_PERMISSIONS_ELEMENT = "//j:permissions";
    private static final String XPATH_PERMISSION_BY_NAME = "//j:permission[j:name='";
    private static final String XPATH_PRINCIPAL_BY_NAME = "//j:principal[j:name='";
    private static final String XPATH_ALL_PRINCIPAL_ELEMENTS = "//principal";


    /**
     * initialize this XML AuthorizationManager.
     *
     * @param options
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager #init(java.util.Properties)
     */
    @Inject
    public XmlAuthorizationManager(@ApplicationName String applicationName, @AuthorizationManagerOptions Map<String, String> options) {
        super(options);
        this.setApplicationName(applicationName);
        super.options = options;
        fileLocation = options.get(JGuardAuthorizationManagerMarkups.AUTHORIZATION_XML_FILE_LOCATION.getLabel());
        if (fileLocation == null || "".equals(fileLocation)) {
            throw new IllegalArgumentException(JGuardAuthorizationManagerMarkups.AUTHORIZATION_XML_FILE_LOCATION.getLabel() + " argument for XMLAuthorizationManager is null or empty " + fileLocation);
        }
        init();

    }


    /**
     * initialize permissions and Principals.
     */
    private void init() {
        //remove white spaces on both ends
        fileLocation = fileLocation.trim();
        //replace the white space remaining in the internal string structure
        // by the '%20' pattern
        fileLocation = fileLocation.replaceAll(" ", "%20");

        if (logger.isDebugEnabled()) {
            logger.debug("fileLocation=" + fileLocation);
        }
        URL url;
        try {
            url = new URL(XMLUtils.resolveLocation(fileLocation));
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        document = XMLUtils.read(url, J_GUARD_PRINCIPALS_PERMISSIONS_2_00_XSD);
        root = document.getRootElement();

        initPermissions();
        initPrincipals();
    }


    /**
     * build Principals and associate to them their permissions.
     */
    private void initPrincipals() {

        Element principalsElement = root.element(PRINCIPALS);
        //convert a List into a Set because it is a functional requirement
        //=> you can't have two same principals
        List principalsElementList = principalsElement.elements(PRINCIPAL);

        for (Object aPrincipalsElementList : principalsElementList) {
            Element principalElement = (Element) aPrincipalsElementList;
            String className = principalElement.element(CLASS).getStringValue();
            String name;

            if (className.equals(RolePrincipal.class.getName())) {
                name = RolePrincipal.getName(principalElement.element(NAME).getStringValue(), getApplicationName());

            } else {
                name = principalElement.element(NAME).getStringValue();
            }
            Principal ppal = PrincipalUtils.getPrincipal(className, name);
            if (className.equals(RolePrincipal.class.getName())) {
                buildJGuardPrincipal(principalElement, ppal);
            }
            //add principal created to the Principals Set
            principalsSet.add(ppal);
            //add principal created to the principals map
            principals.put(getLocalName(ppal), ppal);
        }

        assemblyHierarchy();
    }


    /**
     * build permissions and domain maps.
     */
    private void initPermissions() {

        Element domainsElement = root.element(PERMISSIONS);
        List permissionsElementList = domainsElement.elements(PERMISSION);

        for (Object permissionElementList : permissionsElementList) {

                Element permissionElement = (Element) permissionElementList;
                Element actionsElement = permissionElement.element(ACTIONS);
                List actionsList = actionsElement.elements();
                Iterator itActions = actionsList.iterator();
                StringBuffer sbActions = new StringBuffer();
                int i = 0;
                while (itActions.hasNext()) {
                    String actionTemp = ((Element) itActions.next()).getText();
                    if (i != 0) {
                        sbActions.append(',');
                    }
                    sbActions.append(actionTemp);
                    i++;
                }
                String actions = sbActions.toString();
                String permissionName = permissionElement.element(NAME).getTextTrim();

                String className = permissionElement.element(CLASS).getTextTrim();
                Permission perm;
                try {
                    perm = PermissionUtils.getPermission(className, permissionName, actions);
                } catch (ClassNotFoundException e) {
                    logger.warn(e.getMessage());
                    continue;
                }

                //add the permission to the global map
                permissions.put(perm.getName(), perm);
                permissionsSet.add(perm);

        }
        if(0==permissions.size()){
           throw new IllegalStateException(NO_PERMISSIONS_ARE_BUILT_FROM_XML_FILE);
        }
        super.urlp.addAll(permissionsSet);
    }

    /**
     * return needed initialization parameters.
     *
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager #getInitParameters()
     */
    public List getInitParameters() {
        String[] authorizationParams = {FILE_LOCATION};
        return Arrays.asList(authorizationParams);
    }


    private Element getElement(String xpath) {
        XPath xp2 = DocumentHelper.createXPath(xpath);
        Map<String, String> uris = new HashMap<String, String>();
        uris.put(STRING_NAMESPACE_PREFIX, HTTP_JGUARD_SOURCEFORGE_NET_XSD_J_GUARD_PRINCIPALS_PERMISSIONS_2_0_0);
        xp2.setNamespaceURIs(uris);

        return (Element) xp2.selectSingleNode(root);
    }

    /**
     * create an URLPermission int the corresponding backend.
     *
     * @param permission Permission
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager #createPermission(java.security.Permission, java.lang.String)
     */
    public void createPermission(Permission permission) throws AuthorizationManagerException {
        String[] actions = permission.getActions().split(",");

        Element permissionsElement = getElement(XPATH_PERMISSIONS_ELEMENT);
        //add the permissionElement reference to the permissionsElement
        Element permissionElement = permissionsElement.addElement(PERMISSION);
        Element nameElement = permissionElement.addElement(NAME);
        nameElement.setText(permission.getName());
        Element classElement = permissionElement.addElement(CLASS);
        classElement.setText(permission.getClass().getName());
        Element actionsElement = permissionElement.addElement(ACTIONS);
        for (String action : actions) {
            Element actionElement = actionsElement.addElement(ACTION);
            actionElement.setText(action);
        }

        //we retrieve the domain corresponding to the domainName
        //and linking together the URLPermission newly created
        //and it
        permissions.put(permission.getName(), permission);
        permissionsSet.add(permission);
        urlp.add(permission);

        try {
            XMLUtils.write(fileLocation, document);
        } catch (IOException e) {
            logger.error("error when create permission " + permission, e);
        }

    }



    /**
     * replace the inital permission with the new one.
     *
     * @param oldPermissionName old permission name
     * @param permission        URLPermission updated
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager #updatePermission(java.lang.String, java.security.Permission, java.lang.String)
     */
    public void updatePermission(String oldPermissionName, Permission permission) throws AuthorizationManagerException {
        //we set the real domain to the updated permission and not a dummy one
        deletePermission(oldPermissionName);
        createPermission(permission);
    }


    /**
     * remove the permission.
     *
     * @param permissionName
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager #deletePermission(java.lang.String)
     */
    public void deletePermission(String permissionName) throws AuthorizationManagerException {
        Element permissionElement = getElement(XPATH_PERMISSION_BY_NAME + permissionName + "']");
        Element domainElement = getElement(XPATH_PERMISSION_BY_NAME + permissionName + "']/..");
        domainElement.remove(permissionElement);
        Permission oldPermission = permissions.remove(permissionName);
        permissions.remove(oldPermission.getName());
        permissionsSet.remove(oldPermission);
        urlp.removePermission(oldPermission);
        removePermissionFromPrincipals(permissionName);

        try {
            XMLUtils.write(fileLocation, document);
        } catch (IOException e) {
            logger.error("deletePermission(String)", e);
        }
    }




    /**
     * create a new Role/principal
     *
     * @param principal principal/role to create
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager #createPrincipal(net.sf.jguard.core.principals.RolePrincipal)
     */
    public void createPrincipal(Principal principal) throws AuthorizationManagerException {
        Element principalsElement = root.element(PRINCIPALS);
        //add the permissionElement reference to the domainElement
        Element principalElement = principalsElement.addElement(PRINCIPAL);
        Element nameElement = principalElement.addElement(NAME);
        //add 'class' Element
        Element classElement = principalElement.addElement(CLASS);
        classElement.setText(principal.getClass().getName());

        nameElement.setText(getLocalName(principal));
        principals.put(getLocalName(principal), principal);
        principalsSet.add(principal);
        if (principal.getClass().equals(RolePrincipal.class)) {
            RolePrincipal ppal = (RolePrincipal) principal;
            insertPermissionsAndInheritance(principalElement, ppal);
        }

        try {
            XMLUtils.write(fileLocation, document);
        } catch (IOException e) {
            logger.error("createRole(RolePrincipal)", e);
        }

    }

    private void insertPermissionsAndInheritance(Element principalElement, RolePrincipal ppal) {
        Element permsRefElement = principalElement.addElement(PERMISSIONS_REF);
        Set perms = ppal.getPermissions();
        for (Object orphanedPerm : perms) {
            Permission perm = (Permission) orphanedPerm;
            Element permRef = permsRefElement.addElement(PERMISSION_REF);
            //add the name attribute
            Attribute nameAttribute = new UserDataAttribute(new QName(NAME));
            nameAttribute.setValue(perm.getName());
            permRef.add(nameAttribute);
        }



        //role inheritance is only supported by RolePrincipal
        if (ppal.getDescendants().size() > 0) {
            Element descendants = principalElement.addElement(DESCENDANTS);

            //add the descendants of this role
            for (RolePrincipal o : ppal.getDescendants()) {
                Element principalRef = descendants.addElement(PRINCIPAL_REF);

                Attribute nameAttribute = new UserDataAttribute(new QName(NAME));
                nameAttribute.setValue(o.getLocalName());
                principalRef.add(nameAttribute);
            }
        }
    }

    /**
     * remove the corrspoding principal/role
     *
     * @param principal name
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager #deletePrincipal(java.security.Principal)
     */
    public void deletePrincipal(Principal principal) throws AuthorizationManagerException {
        if (principal == null) {
            throw new IllegalArgumentException("principal parameter is null ");
        }
        Principal ppalReference = principals.remove(getLocalName(principal));
        if ((ppalReference == null)) {
            logger.warn(" there is no principal intitled " + principal.getName() + " to delete");
            return;
        }
        principalsSet.remove(ppalReference);
        Element principalsElement = root.element(PRINCIPALS);
        Element principalElement = getElement(XPATH_PRINCIPAL_BY_NAME + getLocalName(principal) + "']");
        principalsElement.remove(principalElement);
        if (ppalReference.getClass().equals(RolePrincipal.class)) {
            deleteReferenceInHierarchy((RolePrincipal) ppalReference);
            //delete all the references of this principal
            XMLUtils.deletePrincipalRefs(root, (RolePrincipal) ppalReference);
        }
        try {
            XMLUtils.write(fileLocation, document);
        } catch (IOException e) {
            logger.error("deleteRole(String)", e);
        }
    }



    /**
     * update a principal
     *
     * @param oldPrincipalName name of the principal to be replaced
     * @param principal        new principal
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager #updatePrincipal(java.lang.String, net.sf.jguard.core.principals.RolePrincipal)
     */
    public void updatePrincipal(String oldPrincipalName, Principal principal) throws AuthorizationManagerException {
        Principal oldPal = principals.remove(oldPrincipalName);
        if (oldPal == null) {
            logger.warn(" principal " + oldPrincipalName + " cannot be updated because it does not exists ");
            return;
        }
        principalsSet.remove(oldPal);
        principals.put(getLocalName(principal), principal);
        principalsSet.add(principal);

        try {
            XMLUtils.write(fileLocation, document);
        } catch (IOException e) {
            logger.error("updateRole(String, RolePrincipal)", e);
        }
    }


    /**
     * add permissions and domains references to RolePrincipal.
     *
     * @param principalElement
     * @param ppal
     */
    private void buildJGuardPrincipal(Element principalElement, Principal ppal) {

        RolePrincipal rolePrincipal = (RolePrincipal) ppal;
        Element pel = principalElement.element(PERMISSIONS_REF);
        Collection domainsPrincipal = pel.elements(DOMAIN_REF);
        Iterator itDomainsPrincipal = domainsPrincipal.iterator();

        Collection permissionsPrincipal = pel.elements(PERMISSION_REF);

        //iterate over permissions defined and add them to the principal permissions Set
        for (Object aPermissionsPrincipal : permissionsPrincipal) {
            Element perm = (Element) aPermissionsPrincipal;
            String permissionName = perm.attributeValue(NAME);
            Permission permission = permissions.get(permissionName);
            if (permission == null) {
                logger.warn("initPrincipals() - principal "
                        + rolePrincipal.getName()
                        + " refers to a unknown permission name :"
                        + permissionName);

                continue;
            }
            permissionsSet.add(permission);
            urlp.add(permission);
            rolePrincipal.addPermission(permission);

        }
        //store the links between ascendants
        Element descendants = principalElement.element(DESCENDANTS);
        if (descendants != null) {
            List descendantsElements = descendants.elements(PRINCIPAL_REF);
            Iterator itDescendantsElements = descendantsElements.iterator();
            List<Principal> descendantsNames = new ArrayList<Principal>();
            while (itDescendantsElements.hasNext()) {
                Element descentantItem = (Element) itDescendantsElements.next();
                descendantsNames.add(principals.get(descentantItem.attributeValue(NAME)));
            }

            hierarchyMap.put(getLocalName(rolePrincipal), descendantsNames);
        }
    }

    /**
     * @return <i>true</i> if there is no principals and no permissions.
     *         <i>false</i> otherwise.
     */
    public boolean isEmpty() {
        List principalsList = root.selectNodes(XPATH_ALL_PRINCIPAL_ELEMENTS);
        List permissions = root.selectNodes(XPATH_PERMISSIONS_ELEMENT);
        return !(!principalsList.isEmpty() && !permissions.isEmpty());
    }

    public String exportAsXMLString() {
        return this.document.asXML();
    }

    public void writeAsHTML(OutputStream outputStream) throws IOException {
        HTMLWriter writer = new HTMLWriter(outputStream, OutputFormat.createPrettyPrint());
        writer.write(this.document);
        writer.flush();

    }

    public void writeAsXML(OutputStream outputStream, String encodingScheme) throws IOException {
        OutputFormat outformat = OutputFormat.createPrettyPrint();
        outformat.setEncoding(encodingScheme);
        XMLWriter writer = new XMLWriter(outputStream, outformat);
        writer.write(this.document);
        writer.flush();
    }

    public void exportAsXMLFile(String fileName) throws IOException {
        XMLWriter xmlWriter = null;
        FileWriter fileWriter = null;
        try {
            fileWriter = new FileWriter(fileName);
            xmlWriter = new XMLWriter(fileWriter, OutputFormat.createPrettyPrint());
            xmlWriter.write(document);

        } finally {
            fileWriter.close();
            xmlWriter.close();
        }
    }

    public void refresh() {

    }

}
