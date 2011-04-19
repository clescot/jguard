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
package net.sf.jguard.core.authorization.policy;

import net.sf.jguard.core.authorization.manager.PermissionProvider;
import net.sf.jguard.core.principals.JMXPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.ref.WeakReference;
import java.security.*;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;


/**
 * Jguard Policy implementation:
 * handle all Authorization decisions.
 * This implementation handles multiple policies. It is designed for
 * multiple apps requiring different policies among the same VM. Exemple : webapps.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @author <a href="mailto:zelfdoen@users.sourceforge.net">Theo Niemeijer</a>
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 */
abstract class AbstractMultipleAppPolicy extends JGuardPolicy {

    private Map<Object, WeakReference<PermissionProvider>> permissionProviderRepository;
    private static Logger logger = LoggerFactory.getLogger(AbstractMultipleAppPolicy.class.getName());
    private static final String REGISTER_PERMISSION_PROVIDER_ERROR_MESSAGE = "registerPermissionProvider() - two webapps have got the same classLoader ....application will stop";

    /**
     * constructor.
     */
    AbstractMultipleAppPolicy(Permissions grantedPermissions) {
        super(grantedPermissions);
        logger.info("#######   loading jGuardPolicy " + JGuardPolicy.version + " ###########");

        permissionProviderRepository = new WeakHashMap<Object, WeakReference<PermissionProvider>>();

        loadDefaultPolicy();
    }

    /**
     * constructor used to include the replaced Policy.
     *
     * @param oldPolicy replaced by jGuardPolicy
     */
    AbstractMultipleAppPolicy(Policy oldPolicy, Permissions grantedPermissions) {
        super(grantedPermissions);
        logger.info("#######   loading AbstractMultipleAppPolicy  " + JGuardPolicy.version + " ###########");

        permissionProviderRepository = new WeakHashMap<Object, WeakReference<PermissionProvider>>();
        defaultPolicy = oldPolicy;
    }


    /**
     * refresh all the permissions.
     * if somes changes are made with the permissionManager implementation,
     * this method must be called to reflect these changes.
     * you should use instead <i>public void refresh(Object objectID)</i> JGuardPolicy method
     * to avoid performance issue (refresh all security configurations for all application policies).
     *
     * @see AbstractMultipleAppPolicy#refresh(Object objectID)
     */
    public void refresh() {
        Set keys = permissionProviderRepository.keySet();
        for (Object key : keys) {
            refresh(key);
        }

    }

    /**
     * refresh all the permissions.
     * if somes changes are made with the permissionManager implementation,
     * this method must be called to reflect these changes.
     *
     * @param objectID webapplication's classloader
     * @see AbstractMultipleAppPolicy#refresh()
     */
    void refresh(Object objectID) {
        //we get the webapp corresponding permission manager
        // and call its refresh method
        PermissionProvider pm = getContextPermissionProvider(objectID);

        if (pm != null) {
            // Refresh the permission configuration
            pm.refresh();
        }
    }


    /**
     * Register permission provider. Registers given permission provider instance
     * with the specified classloader instance.
     *
     * @param objectID - Object identifier
     * @param pm       - permission provider
     */
    public void registerPermissionProvider(Object objectID, PermissionProvider pm) {

        if (getContextPermissionProvider(objectID) == null) {
            // Put permission provider in map keyed by classloader
            setContextPermissionProvider(objectID, pm);
        } else {
            logger.error(REGISTER_PERMISSION_PROVIDER_ERROR_MESSAGE);

            //key is not unique => two webapps will have the same authorisation mechanism....ERROR
            throw new IllegalStateException(REGISTER_PERMISSION_PROVIDER_ERROR_MESSAGE);
        }
    }

    /**
     * Unregister permission provider. Removes permission provider associated with
     * the given classloader instance.
     *
     * @param objectID - Object identifier
     */
    public void unregisterPermissionProvider(Object objectID) {

        if (permissionProviderRepository.containsKey(objectID)) {

            // Remove permission provider in map keyed by classloader
            permissionProviderRepository.remove(objectID);
        }
    }

    /**
     * Get context permission provider. This is a helper method that
     * uses weakhashmap and weakreferences to ensure that unloaded classes
     * will become garbage collected.
     *
     * @param objectID - Object identifier
     * @return permission provider which can be null if no one is found
     */
    protected PermissionProvider getContextPermissionProvider(Object objectID) {

        // Get permission provider associated with classloader
        WeakReference ref = permissionProviderRepository.get(objectID);

        if (ref == null) {
            return null;
        }

        // Get permission provider from weak reference

        return (PermissionProvider) ref.get();
    }

    /**
     * Set context permission provider. This is a helper method that
     * uses weakhashmap and weakreferences to ensure that unloaded classes
     * will become garbage collected.
     *
     * @param objectID - Identifier Object
     * @param pm       - permission provider
     */
    private void setContextPermissionProvider(Object objectID, PermissionProvider pm) {

        // Put classloader and its associated permission provider in map
        permissionProviderRepository.put(objectID, new WeakReference<PermissionProvider>(pm));
    }


    /**
     * sees if domain can match permission
     *
     * @param domain     -
     * @param permission - permission to be checked
     * @return <code>true</code> if domain checks permission, <code>false</code> otherwise
     */
    public boolean implies(ProtectionDomain domain, Permission permission) {

        if (domain.getClassLoader() == null) {
            //   domain may be the ProtectionDomain generated
            // during JMX connection. The JMX generated ProtectionDomain
            // has null classLoader, null codeSource, empty permissions and
            // the principals set during JGuardJMXAuthenticator.authenticate().
            // This domain is created in JMXSubjectDomainCombiner.combine(...)
            //   It could also simply be a protection domain with null classloader
            // but not very likely.
            //
            //   The following test searches for a JMXPrincipal to ensure that
            // this null classloader protectionDomain is indeed created for JMX.

            Principal[] principals = domain.getPrincipals();
            boolean jmxHandled = false;
            int i = 0;
            ProtectionDomain newDomain = null;

            while (i < principals.length && !jmxHandled) {
                if (principals[i] instanceof JMXPrincipal) {
                    newDomain = new ProtectionDomain(domain.getCodeSource(),
                            domain.getPermissions(),
                            (ClassLoader) ((JMXPrincipal) principals[i]).getObjectID(),
                            domain.getPrincipals());
                    jmxHandled = true;
                }
                i++;
            }

            if (newDomain != null) {
                // domain is the protectionDomain created in JMXSubjectDomainCombiner
                // a new ProtectionDomain is created based on domain but it adds the
                // classloader got from the JMXPrincipal. super.implies(newDomain,...);
                // invokes the method getPermissions(newDomain) and with this new domain,
                // getPermission is able to get the PermissionProvider of the webapp whose
                // MBean are monitored by JMX.
                return super.implies(newDomain, permission);
            }
        }
        return super.implies(domain, permission);
    }


    public void addAlwaysGrantedPermissions(ClassLoader cl, Permissions alwaysGrantedPermissions) {
        PermissionProvider pm = getContextPermissionProvider(cl);
        if (pm == null) {
            logger.error(" classloader is not bound to a PermissionProvider registered in the MultipleAppPolicy ");
            logger.error(" permissions always granted cannot be added ");
        } else {
            pm.addAlwaysGrantedPermissions(alwaysGrantedPermissions);
        }
    }
}
