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
package net.sf.jguard.core.authorization.policy;

import net.sf.jguard.core.authorization.manager.PermissionProvider;
import net.sf.jguard.core.authorization.permissions.AuditPermissionCollection;
import net.sf.jguard.core.authorization.permissions.PermissionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.util.Enumeration;
import java.util.Properties;


/**
 * JGuard Policy abstract implementation.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 * @see AbstractMultipleAppPolicy
 * @see MultipleAppPolicy
 * @see SingleAppPolicy
 */
public abstract class JGuardPolicy extends java.security.Policy {

    private static final String LIB = "lib";
    private static final String SECURITY = "security";
    private static final String J_GUARD_POLICY = "jGuard.policy";
    private static final String JGUARD_POLICY_LOCATION = File.separator + JGuardPolicy.LIB + File.separator + JGuardPolicy.SECURITY + File.separator + JGuardPolicy.J_GUARD_POLICY;
    private static final String DEFAULT_POLICY = "defaultPolicy";
    private static final String JAVA_HOME = "java.home";
    //old Policy instance replaced by JGuardPolicy
    Policy defaultPolicy;
    //old Policy instance Class replaced by JGuardPolicy
    private static Class policyClass;
    private static Logger logger = LoggerFactory.getLogger(JGuardPolicy.class.getName());
    public static final String version = "2.0.0 beta 8";

    //well-known java policies
    private static final String GNU_JAVA_SECURITY_POLICY_FILE = "gnu.java.security.PolicyFile";

    private static final String SUN_SECURITY_PROVIDER_POLICY_FILE = "sun.security.provider.PolicyFile";
    protected Permissions grantedPermissions;


    /**
     * default constructor.
     * @param grantedPermissions
     */
    public JGuardPolicy(Permissions grantedPermissions) {
        this.grantedPermissions = grantedPermissions;
    }

    /**
     * load the default Policy implementation class.
     */
    void loadDefaultPolicy() {
        //the securityManager is not set
        if (System.getSecurityManager() == null) {
            String javaHome = System.getProperty(JGuardPolicy.JAVA_HOME);
            Properties props = new Properties();
            String defPolicy = null;
            File file;
            FileInputStream fileInputStream = null;
            file = new File(javaHome + JGuardPolicy.JGUARD_POLICY_LOCATION);
            try {
                fileInputStream = new FileInputStream(file);
                props.load(fileInputStream);
                defPolicy = props.getProperty(JGuardPolicy.DEFAULT_POLICY);
            } catch (FileNotFoundException e) {
                logger.info("loadDefaultPolicy() -  jGuard.policy is not found " + e.getMessage());
            } catch (IOException e) {
                logger.info("loadDefaultPolicy() -  jGuard.policy is not reachable " + e.getMessage());
            } finally {

                try {
                    if (fileInputStream != null) {
                        fileInputStream.close();
                    }
                } catch (IOException e) {
                    logger.error(e.getMessage(), e);
                }
            }

            try {

                if (defPolicy == null) {
                    logger.info("loadDefaultPolicy() -  'defaultPolicy' field in the jGuard.Policy file is not defined ");
                    logger.info("loadDefaultPolicy() -  jGuard try to discover the default one ");
                    // we search the default policy class
                    policyClass = findDefaultPolicy();
                } else {
                    // we use the defined default policy class
                    policyClass = Class.forName(defPolicy);
                }
            } catch (ClassNotFoundException e1) {
                logger.info("loadDefaultPolicy() - the default policy class cannot be found " + e1.getMessage());
            }

            //the securityManager is set
        } else {
            policyClass = findDefaultPolicy();
        }

        try {
            defaultPolicy = (Policy) policyClass.newInstance();
        } catch (InstantiationException e2) {
            logger.info("loadDefaultPolicy() - the default policy class cannot be instantiated"
                    + e2.getMessage());
        } catch (IllegalAccessException e2) {
            logger.info("loadDefaultPolicy() - the default policy class cannot be accessed "
                    + e2.getMessage());
        }
    }

    /**
     * JGuard Policy act as a wrapper for this method.
     * it delegates to default's Policy implementation defined in Jguard.policy file, this method.
     *
     * @param codesource identify an archive like a jar
     * @return all the permissions own by the CodeSource
     * @see java.security.Policy#getPermissions(java.security.CodeSource)
     */
    public PermissionCollection getPermissions(CodeSource codesource) {
        PermissionCollection permColl = defaultPolicy.getPermissions(codesource);
        return new AuditPermissionCollection(permColl, codesource);
    }

    /**
     * retrieve all user's permissions.
     * if this protectionDomain is protected by jGuard,
     * we add the jGuard additional permissions to the permissionCollection
     * obtained with the defaultPolicy implementation
     * when the SecurityManager is set.
     * otherwise, the only PermissionCollection created by jGuard is returned.
     *
     * @param protectionDomain
     * @return permissions collection
     * @see java.security.Policy#getPermissions(java.security.ProtectionDomain)
     */
    public PermissionCollection getPermissions(final ProtectionDomain protectionDomain) {

        // Get classloader for protection domain
        ClassLoader cl = protectionDomain.getClassLoader();
        // Get permission provider associated with classloader

        final PermissionProvider pm = getContextPermissionProvider(cl);


        // execute these instruction under extended privileges
        PermissionCollection pc = (PermissionCollection) AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                return getPermissions(protectionDomain, pm);
            }
        });

        //include always granted permissions
        PermissionCollection mergedPc = PermissionUtils.mergePermissionCollections(pc, grantedPermissions);
        //include permissions from CodeSource
        mergedPc = PermissionUtils.mergePermissionCollections(mergedPc, getPermissions(protectionDomain.getCodeSource()));
        return new AuditPermissionCollection(mergedPc, protectionDomain);
    }

    protected abstract PermissionProvider getContextPermissionProvider(Object key);


    public abstract void refresh();

    private PermissionCollection getPermissions(ProtectionDomain protectionDomain, PermissionProvider permissionProvider) {
        PermissionCollection pc = null;
        if (System.getSecurityManager() != null) {
            pc = defaultPolicy.getPermissions(protectionDomain);
        }

        //if this protection domain is protected by jGuard
        if (permissionProvider != null) {
            //retrieve permissions from roles owned by the user which are active
            //and resolve regexp in permissions
            PermissionCollection pc2 = permissionProvider.getPermissions(protectionDomain);

            //the SecurityManager is set,we merge the default permissionCollection and the permissionCollection returned by jGuard
            if (System.getSecurityManager() != null && pc != null) {
                Enumeration enumeration = pc2.elements();
                while (enumeration.hasMoreElements()) {
                    pc.add((Permission) enumeration.nextElement());
                }
            } else {
                //there is no SecurityManager set
                //we return only the permissionCollection obtained by jGuard
                pc = pc2;
            }
        }

        return pc;
    }


    /**
     * discover the default policy installed on the running platform.
     *
     * @return defaultPolicy class
     */
    private static Class findDefaultPolicy() {
        //known default policies class => do you know other java.lang.security.Policy implementations?
        String[] policies = {SUN_SECURITY_PROVIDER_POLICY_FILE, GNU_JAVA_SECURITY_POLICY_FILE};
        Class defaultPolicyClass = null;
        for (String policy : policies) {
            try {
                defaultPolicyClass = Class.forName(policy);
            } catch (ClassNotFoundException e) {
                logger.debug("findDefaultPolicy() - " + policy + " is not the defaultPolicy class ");
                continue;
            }
            logger.debug("findDefaultPolicy() - " + policy + " is the defaultPolicy class ");
            break;
        }
        if (null == defaultPolicyClass) {
            logger.debug("findDefaultPolicy() -  no defaultPolicy class has been found ");
        }
        return defaultPolicyClass;
    }


}
