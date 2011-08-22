/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.

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

import net.sf.ehcache.CacheException;
import net.sf.jguard.core.authorization.manager.AuthorizationManager;
import net.sf.jguard.core.authorization.manager.AuthorizationManagerException;
import net.sf.jguard.core.authorization.permissions.*;
import net.sf.jguard.core.authorization.policy.ProtectionDomainUtils;
import net.sf.jguard.core.principals.PrincipalUtils;
import net.sf.jguard.core.principals.RolePrincipal;
import net.sf.jguard.core.principals.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.*;

/**
 * Abstract class inherited by all the AuthorizationManager implementations.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
abstract class AbstractAuthorizationManager implements AuthorizationManager {
    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(AbstractAuthorizationManager.class.getName());


    protected String applicationName = null;
    protected Map<String, Principal> principals;
    protected Set<Principal> principalsSet;
    //we add also this Set of domains to certify Domain unicity
    protected JGPermissionCollection urlp;
    //store all the permissions of all the domains
    protected Map<String, Permission> permissions;
    protected Set<Permission> permissionsSet;
    //store the permissions set associated with the domain ids
    //  store the hierarcy while assembly the principals to after link
    protected Map<String, List<Principal>> hierarchyMap;
    protected Map options;
    private boolean negativePermissions;
    private boolean permissionResolutionCaching;

    //permissions always granted set dynamically at startup
    protected Permissions alwaysGrantedPermissions = null;
    private static final int SALT = 99999;
    private static final String TRUE = "true";

    /**
     * initialize AuthorizationManager implementation.
     *
     */
    public AbstractAuthorizationManager(String applicationName,boolean negativePermissions,boolean permissionResolutionCaching) {
        this.applicationName = applicationName;
        this.negativePermissions = negativePermissions;
        this.permissionResolutionCaching = permissionResolutionCaching;
        principals = new HashMap<String, Principal>();
        principalsSet = new TreeSet<Principal>();
        permissions = new HashMap<String, Permission>();
        permissionsSet = new HashSet<Permission>();
        hierarchyMap = new HashMap<String, List<Principal>>();
        alwaysGrantedPermissions = new Permissions();
        if (negativePermissions) {
            this.urlp = new JGNegativePermissionCollection();
        } else {
            this.urlp = new JGPositivePermissionCollection();
        }
        //permission caching section
        if (!permissionResolutionCaching) {
            PermissionUtils.setCachesEnabled(false);
        } else {
            // by default, permission resolution caching is activated
            try {
                PermissionUtils.createCaches();
                PermissionUtils.setCachesEnabled(true);
            } catch (CacheException e) {
                logger.warn("Failed to activate permission resolution caching : " + e.getMessage(), e);
                PermissionUtils.setCachesEnabled(false);
            }
        }
    }

    /**
     * must be called by subclass constructors at the end to check that base objects are well initialized.
     * @throws IllegalStateException
     */
    protected void checkInitialState()throws IllegalStateException{
        if (null==applicationName||"".equals(applicationName)){
            throw new IllegalStateException("applicationName["+applicationName+"] must not be null or empty");
        }

        if(permissions.size()==0 ||permissionsSet.size()==0){
            throw new IllegalStateException("permissions["+permissions.size()+"] or permissionsSet["+permissionsSet.size()+"] is empty");
        }

        if(principals.size()==0 ||principalsSet.size()==0){
            throw new IllegalStateException("principals["+principals.size()+"] or principalsSet["+principalsSet.size()+"] is empty");
        }

    }

    /**
     * define the application's name, and propagate it into Principals.
     * @param applicationName
     */
    protected void setApplicationNameForPrincipals(String applicationName) {

        for (Principal aPrincipalsSet : principalsSet) {
            RolePrincipal principalTemp = (RolePrincipal) aPrincipalsSet;
            principalTemp.setApplicationName(applicationName);
        }
        for (Principal principal1 : principals.values()) {
            RolePrincipal principal = (RolePrincipal) principal1;
            principal.setApplicationName(applicationName);
        }

    }


    /**
     * with a collection of URLPermissions names, provide the corresponding
     * set of URLPermissions.
     *
     * @param permissionNames collection of permission names to grab.
     * @return URLPermission's Set
     */
    public Set<Permission> getPermissions(Collection permissionNames) {
        Set<Permission> perms = new HashSet<Permission>();

        for (Object permissionName1 : permissionNames) {
            Permission perm;
            String permissionName = (String) permissionName1;
            try {
                perm = urlp.getPermission(permissionName);
                perms.add(perm);
            } catch (NoSuchPermissionException e) {
                logger.debug(" permission " + permissionName + " not found in JGPermissionCollection ");
            }
        }

        return perms;
    }


    /**
     * @see AuthorizationManager
     */
    public abstract void refresh();


    /**
     * compare declared Principals in the application, with principals set of the user.
     * for the principals of the user, we retrieve corresponding permissions declared in the application,
     * and we regroup them in a PermissionCollection.
     *
     * @param protectionDomain
     * @return PermissionCollection
     * @see AuthorizationManager
     * @see net.sf.jguard.core.authorization.manager.PermissionProvider
     */
    public PermissionCollection getPermissions(ProtectionDomain protectionDomain) {
        Set<Principal> ppals = new HashSet<Principal>(Arrays.asList(protectionDomain.getPrincipals()));
        UserPrincipal userPrincipal = ProtectionDomainUtils.getUserPrincipal(protectionDomain);
        RolePrincipal tempUserPrincipal;
        RolePrincipal tempDefinedPrincipal;

        Iterator definedPrincipalsIt;

        JGPermissionCollection urlpUser;
        if (!isNegativePermissions()) {
            urlpUser = new JGPositivePermissionCollection();
        } else {
            urlpUser = new JGNegativePermissionCollection();
        }

        //add all RolePrincipal permissions to JGPermissionCollection
        for (Object ppal1 : ppals) {
            Principal ppal = (Principal) ppal1;
            if (!(ppal instanceof RolePrincipal)) {
                //we skip principal which are not RolePrincipal
                //only jGuardPrincipals own permissions
                continue;
            } else {
                tempUserPrincipal = (RolePrincipal) ppal;
            }

            //we don't add the RolePrincipal if its definition is false
            if (!PrincipalUtils.evaluatePrincipal(tempUserPrincipal, userPrincipal)) {
                continue;
            }

            if (logger.isDebugEnabled()) {
                logger.debug("  user's principal name=" + tempUserPrincipal.getLocalName());
                logger.debug(" user's principal applicationName="
                        + tempUserPrincipal.getApplicationName());
            }
            definedPrincipalsIt = principalsSet.iterator();
            //we search the corresponding defined Principal
            while (definedPrincipalsIt.hasNext()) {
                tempDefinedPrincipal = (RolePrincipal) definedPrincipalsIt.next();
                if (logger.isDebugEnabled()) {
                    logger.debug("system's principal name="
                            + tempDefinedPrincipal.getLocalName());
                    logger.debug("system's principal applicationName="
                            + applicationName);
                }

                //if RolePrincipal owned by the user(Authentication side) matches
                //with the RolePrincipal owned by the application(Authorization side),
                //we add all the related permissions in the PermissionCollection of the user
                if (tempDefinedPrincipal.equals(tempUserPrincipal)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("principal name="
                                + tempUserPrincipal.getLocalName()
                                + " is declared in this application ");
                    }
                    urlpUser.addAll(tempDefinedPrincipal.getAllPermissions());
                    Set tempset = tempDefinedPrincipal.getAllPermissions();

                    if (logger.isDebugEnabled()) {
                        logger.debug("permissions granted are :"
                                + tempset.toString());
                    }

                    break;
                }
            }
        }

        //we add the permissions bound to the protectionDomain assigned statically by the classloader
        if (protectionDomain.getPermissions() != null) {
            urlpUser.addAll(protectionDomain.getPermissions());
        }

        if (logger.isDebugEnabled()) {
            logger.debug(" user has got " + urlpUser.size() + " permissions: \n" + urlpUser);
        }

        //resolve regexp in permissions
        JGPermissionCollection resolvedPermissions = (JGPermissionCollection) PrincipalUtils.evaluatePermissionCollection(protectionDomain, (PermissionCollection) urlpUser);
        //we remove unresolved permissions
        //and replace them with the resolved one
        //we do that to preserve the JGpermissionCollection subclass
        //positive or negative
        urlpUser.clear();
        urlpUser.addAll(resolvedPermissions);

        //TODO CGA add Dynamic Separation Of Duty (DSOD) feature specified in RBAC
        //(Role based Access Control)
        //we will implement it as a Permissions subclass
        //it will check permissions against DSO constraint in a static way
        //in conjunction with the class WorkflowCheckerFactory

        return PermissionUtils.mergePermissionCollections(urlpUser, alwaysGrantedPermissions);
    }

    /**
     * clone a RolePrincipal/Role and set its name with the name of the Principal to clone plus
     * a random number.
     *
     * @param roleName RolePrincipal name to clone
     * @return cloned RolePrincipal with a different name : original JguardPrincipal name + Random integer betweeen 0 and 99999
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     */
    public Principal clonePrincipal(String roleName) throws AuthorizationManagerException {
        Random rnd = new Random();
        String cloneName = roleName + rnd.nextInt(SALT);

        return clonePrincipal(roleName, cloneName);
    }

    /**
     * clone a RolePrincipal/Role and set its name.
     *
     * @param roleName  RolePrincipal name to clone
     * @param cloneName RolePrincipal cloned name
     * @return cloned RolePrincipal with a different name : original JguardPrincipal name + Random integer betweeen 0 and 99999
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     */
    public Principal clonePrincipal(String roleName, String cloneName) throws AuthorizationManagerException {
        
        if(null==roleName ||"".equals(roleName)){
            throw new IllegalArgumentException("roleName must not be null or an empty string");
        }

        if(null==cloneName ||"".equals(cloneName)){
            throw new IllegalArgumentException("cloneName must not be null or an empty string");
        }

        cloneName = RolePrincipal.getName(cloneName, applicationName);
        Principal role = principals.get(roleName);
        if(null==role){
            throw new IllegalStateException("role with the name "+roleName+" owning to the application "+applicationName+" cannot be found");
        }
        Principal clone;
        if (role instanceof RolePrincipal) {
            clone = new RolePrincipal(cloneName, (RolePrincipal) role);
        } else
            clone = PrincipalUtils.getPrincipal(role.getClass().getName(), cloneName);

        //persist the newly created clone
        createPrincipal(clone);

        return clone;
    }




    /**
     * read an URLPermission.
     *
     * @param permissionName
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     * @see AuthorizationManager
     */
    public Permission readPermission(String permissionName) throws AuthorizationManagerException {
        try {
            return urlp.getPermission(permissionName);
        } catch (NoSuchPermissionException e) {
            throw new AuthorizationManagerException(" permission " + permissionName + " not found ", e);
        }
    }



    /**
     * return the corresponding application role.
     *
     * @return role or null if not found
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     * @see AuthorizationManager#readPrincipal(java.lang.String)
     */
    public Principal readPrincipal(String roleName) throws AuthorizationManagerException {
        return principals.get(roleName);
    }



    /**
     * <p>Update the permissions from jGuardPrincipals <b>and</b> the associated domain.</p>
     * <p><b>Note:</b> This method is need because, first, there are no warranty that the reference
     * of domain in the RolePrincipal object are the same from domainsSet and map and, second, the
     * getPermissions method from RolePrincipal don't load the permissions from domains objects
     * (it use a internal set of permissions).</p>
     *
     * @param permission whose domain will be updated in the principals
     */
    protected void updatePrincipals(Permission permission) {
        for (Object aPrincipalsSet : principalsSet) {
            RolePrincipal principal = (RolePrincipal) aPrincipalsSet;
                principal.getPermissions().remove(permission);
                principal.getPermissions().add(permission);

        }
    }





    /**
     * Remove the permission from all principals that have relationship with this permission.
     *
     * @param permissionName the name of the permission that will be removed
     */
    protected void removePermissionFromPrincipals(String permissionName) {
        Permission permission = permissions.get(permissionName);

        for (Principal aPrincipalsSet : principalsSet) {
            RolePrincipal principal = (RolePrincipal) aPrincipalsSet;
            if (principal.getPermissions().contains(permission)) {
                principal.getPermissions().remove(permission);
                logger.debug("removePermissionFromPrincipals: " + permission);
            }
        }
    }



    /**
     * add the permission to the corresponding role.
     * if the permission is not persisted, we persist it and create
     * a corresponding Domain with the same name.
     *
     * @param roleName role updated
     * @param perm     permission to add
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     */
    public void addToPrincipal(String roleName, Permission perm) throws AuthorizationManagerException {
        RolePrincipal role = (RolePrincipal) principals.get(roleName);
        if (role == null) {
            throw new SecurityException(" Principal/role " + roleName + " does not exists ");
        }
        //if permission does not exists, we add it
        // and create a corresponding domain with the same name
        if (!permissionsSet.contains(perm)) {
            permissionsSet.add(perm);
            permissions.put(perm.getName(), perm);
            createPermission(perm);
        }
        role.addPermission(perm);
    }


    /**
     * This commands establishes a new immediate inheritance relationship
     * between the existing principals/principals roleAsc and the roleDesc.
     * The command is valid if and only if the role roleAsc is not an immediate
     * ascendant of roleDesc, and descendant does
     * not properly inherit roleAsc principal/role (in order to avoid cycle creation).
     *
     * @param principalAscName  the principal/role <strong>local</strong> name that will inherite.
     * @param principalDescName the principal/role <strong>local</strong> name that will be inherited.
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *          if the inheritance already exists or create a cycle.
     */
    public void addInheritance(String principalAscName, String principalDescName) throws AuthorizationManagerException {

        //getting the principals
        RolePrincipal principalAsc = (RolePrincipal) principals.get(principalAscName);
        RolePrincipal principalDesc = (RolePrincipal) principals.get(principalDescName);

        if (principalAscName.equals(principalDescName)) {
            logger.error("ascendant and descendant cannot be the same principal ");
            throw new AuthorizationManagerException("ascendant and descendant cannot be the same principal ");
        }

        if (principalAsc == null) {
            logger.error("Role " + principalAscName + " not found!");
            throw new AuthorizationManagerException("Role " + principalAscName + " not found!");
        }

        if (principalDesc == null) {
            logger.error("Role " + principalDescName + " not found!");
            throw new AuthorizationManagerException("Role " + principalDescName + " not found!");
        }

        if (!RolePrincipal.class.isAssignableFrom(principalAsc.getClass())
                || !RolePrincipal.class.isAssignableFrom(principalDesc.getClass())) {
            throw new AuthorizationManagerException(" role inheritance is only supported by RolePrincipal \n roleAsc class=" + principalAsc.getClass().getName() + " \n roleDesc class=" + principalDesc.getClass().getName());
        }

        //check if the roleAsc is immediate ascendant of roleDesc
        for (Object o : principalAsc.getDescendants()) {
            if (principalDesc.equals(o)) {
                logger.error("Role " + principalAscName + " is immediate ascendant of role " + principalDescName + "!");
                throw new AuthorizationManagerException("Role " + principalAscName + " is immediate ascendant of role " + principalDescName + "!");
            }
        }

        //check if roleDesc inherit roleAsc
        //use a stack instead of a recursive method
        Stack<RolePrincipal> rolesToCheck = new Stack<RolePrincipal>();
        //used to check first all principals from one level before check the next level
        Stack<RolePrincipal> rolesFromNextLevel = new Stack<RolePrincipal>();
        rolesToCheck.addAll(principalDesc.getDescendants());

        while (!rolesToCheck.isEmpty()) {
            RolePrincipal role = rolesToCheck.pop();
            if (principalAsc.equals(role)) {
                logger.error("Role " + principalAscName + " cannot inherit role "
                        + principalDescName + " because " + principalDescName + " inherit "
                        + principalAscName);
                throw new AuthorizationManagerException("Role " + principalAscName + " cannot inherit role "
                        + principalDescName + " because " + principalDescName + " inherit "
                        + principalAscName);
            }

            rolesFromNextLevel.addAll(role.getDescendants());

            //is time to go to next level
            if (rolesToCheck.isEmpty()) {
                rolesToCheck.addAll(rolesFromNextLevel);

                //clear the second level stack
                rolesFromNextLevel.clear();
            }
        }

        //update in-memory role
        principalAsc.getDescendants().add(principalDesc);

        //update xml
        updatePrincipal(principalAsc);
    }

    /**
     * @param roleAscName  the role that inherit.
     * @param roleDescName the role that is inherited.
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *          if the inheritance already exists or create a cycle.
     */
    public void deleteInheritance(String roleAscName, String roleDescName) throws AuthorizationManagerException {
        RolePrincipal roleAsc = (RolePrincipal) principals.get(roleAscName);
        roleAsc.getDescendants().remove(principals.get(roleDescName));
        updatePrincipal(roleAsc);
    }

    /**
     * replace the inital principal with the new one.
     *
     * @param principal RolePrincipal updated
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager
     */
    public void updatePrincipal(Principal principal) throws AuthorizationManagerException {
        deletePrincipal(principal);
        createPrincipal(principal);
        logger.debug(" updated principal=" + principal);
    }

    /**
     * assembly the hierarchy of jGuardPrincipals.
     */
    protected void assemblyHierarchy() {
        //now that every principal is mapped, assembly the hierarchy.
        for (String ascendantName : hierarchyMap.keySet()) {
            RolePrincipal ascendant = (RolePrincipal) principals.get(ascendantName);

            for (Object o : hierarchyMap.get(ascendantName)) {
                RolePrincipal descendant = (RolePrincipal) o;
                ascendant.getDescendants().add(descendant);
                logger.debug("Role " + ascendantName + " inherits from role " + descendant.getLocalName());
            }
        }

    }

    /**
     * @param principal
     */
    protected void deleteReferenceInHierarchy(RolePrincipal principal) {
        String principalName = principal.getLocalName();

        //clean the hierarchy
        for (String ascendantName : hierarchyMap.keySet()) {
            if (principalName.equals(ascendantName)) {
                //we remove in memory the deleted principal
                hierarchyMap.remove(ascendantName);
            } else {
                List descendants = hierarchyMap.get(ascendantName);
                descendants.remove(principal);
            }
        }

        //clean descendants references in the principal Map
        Collection values = principals.values();
        for (Object value : values) {
            RolePrincipal ppalTemp = (RolePrincipal) value;
            ppalTemp.getDescendants().remove(principal);
        }

        //clean descendants references in the principal Set
        for (Principal aPrincipalsSet : principalsSet) {
            RolePrincipal ppalTemp = (RolePrincipal) aPrincipalsSet;
            ppalTemp.getDescendants().remove(principal);
        }

    }

    /**
     * return the principal's Set.
     *
     * @return principal's Set
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager#listPrincipals()
     */
    public Set<Principal> listPrincipals() {
        return principalsSet;
    }

    /**
     * return all the permissions.
     *
     * @return URLPermission container
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager#listPermissions()
     */
    public JGPermissionCollection listPermissions() {
        return new JGPositivePermissionCollection(permissionsSet);
    }


    /**
     * import data from the provided AbstractAuthorizationManager into
     * our AuthorizationManager.
     *
     * @param authManager
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     */
    public void importAuthorizationManager(AuthorizationManager authManager) throws AuthorizationManagerException {
        if (authManager.isEmpty()) {
            logger.warn(" authManager to import is empty ");
            return;
        }
        //import domains set and associated permissions
        Set<Permission> permissions = authManager.getPermissionsSet();
            for (Permission permission : permissions) {
                createPermission(permission);
            }


        //import principal set
        Set<Principal> principals = authManager.getPrincipalsSet();
        for (Principal principal : principals) {
            createPrincipal(principal);
        }


        //import principal inheritance
        for (Principal principal : principals) {
            if (principal instanceof RolePrincipal) {
                RolePrincipal ppal = (RolePrincipal) principal;
                Set descendants = ppal.getDescendants();
                for (Object descendant : descendants) {
                    RolePrincipal descPrincipal = (RolePrincipal) descendant;
                    addInheritance(getLocalName(principal), getLocalName(descPrincipal));
                }
            }
        }


    }


    public final Set<Permission> getPermissionsSet() {
        return new HashSet<Permission>(permissionsSet);
    }

    public final Map<String, Principal> getPrincipals() {
        return new HashMap<String, Principal>(principals);
    }


    public final Set<Principal> getPrincipalsSet() {
        return new HashSet<Principal>(principalsSet);
    }

    protected static String getLocalName(Principal principal) {

        String name;
        if (principal instanceof RolePrincipal) {
            RolePrincipal rolePrincipal = (RolePrincipal) principal;
            name = rolePrincipal.getLocalName();
        } else {
            name = principal.getName();
        }
        return name;
    }

    /**
     * add some permissions always granted by this Policy, like permission used to
     * <i>logoff</i> in webapp, or permissions used to reached the <i>AccessDenied</i> page.
     *
     * @param permissions permissions always granted by this Policy
     */
    final public void addAlwaysGrantedPermissions(Permissions permissions) {
        Enumeration perms = permissions.elements();
        while (perms.hasMoreElements()) {
            alwaysGrantedPermissions.add((Permission) perms.nextElement());
        }
    }


    public String getApplicationName() {
        return applicationName;
    }

    public boolean isNegativePermissions() {
        return negativePermissions;
    }

    public boolean isPermissionResolutionCaching() {
        return permissionResolutionCaching;
    }
}

