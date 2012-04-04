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
package net.sf.jguard.core.principals;


import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.authorization.permissions.PermissionUtils;
import org.apache.commons.jexl.Expression;
import org.apache.commons.jexl.ExpressionFactory;
import org.apache.commons.jexl.JexlContext;
import org.apache.commons.jexl.JexlHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.*;


/**
 * Utility class to instantiate a PersistedPrincipal implementation.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public final class PrincipalUtils {

    private static final Logger logger = LoggerFactory.getLogger(PrincipalUtils.class.getName());


    private PrincipalUtils() {

    }


    /**
     * instantiate PersistedPrincipal implementations.
     *
     * @param className implementation class
     * @param name
     * @return PersistedPrincipal implementation instance
     */
    public static Principal getPrincipal(String className, String name) {
        Principal ppal = null;
        Class clazz = null;

        try {
            clazz = Class.forName(className);
        } catch (ClassNotFoundException e) {
            logger.error("", e);
        }

        Constructor constructor = null;
        try {
            constructor = clazz.getConstructor(String.class);
        } catch (SecurityException e) {
            logger.error("", e);
        } catch (NoSuchMethodException e) {
            logger.error("", e);
        }

        if (constructor != null) {
            try {
                ppal = (Principal) constructor.newInstance(name);
            } catch (IllegalArgumentException e) {
                logger.error("", e);
            } catch (InstantiationException e) {
                logger.error("", e);
            } catch (IllegalAccessException e) {
                logger.error("", e);
            } catch (InvocationTargetException e) {
                logger.error("", e);
            }
        } else {
            throw new IllegalArgumentException(" the provided Class=" + className + " has'nt got any constructor with a String argument ");
        }

        return ppal;
    }


    /**
     * instantiate PersistedPrincipal implementations
     *
     * @param clazz           implementation class
     * @param parameterTypes
     * @param parameterValues
     * @return instantiated principal
     */
    public static Principal getPrincipal(Class clazz, Class[] parameterTypes, Object[] parameterValues) {
        Principal ppal = null;

        Constructor constructor = null;
        try {
            constructor = clazz.getConstructor(parameterTypes);
        } catch (SecurityException e) {
            logger.error("", e);
        } catch (NoSuchMethodException e) {
            logger.error("", e);
        }

        if (constructor != null) {
            try {
                ppal = (Principal) constructor.newInstance(parameterValues);
            } catch (IllegalArgumentException e) {
                logger.error("", e);
            } catch (InstantiationException e) {
                logger.error("", e);
            } catch (IllegalAccessException e) {
                logger.error("", e);
            } catch (InvocationTargetException e) {
                logger.error("", e);
            }
        }

        return ppal;
    }

    /**
     * clone deeply a set of {@link BasePrincipal} subclasses instances.
     *
     * @param principals
     * @return
     * @throws CloneNotSupportedException
     */
    public static Set<Principal> clonePrincipalsSet(Set<? extends Principal> principals) throws CloneNotSupportedException {
        Set<Principal> clonedPrincipals = new HashSet<Principal>();
        for (Principal principal : principals) {
            BasePrincipal ppal = (BasePrincipal) principal;
            clonedPrincipals.add((Principal) ppal.clone());
        }
        return clonedPrincipals;
    }

    /**
     * check principal Set against global Permissions.
     *
     * @param globalPermissions
     * @param principals
     */
    public static void checkPrincipals(Set globalPermissions, Set<RolePrincipal> principals) {
        Iterator<RolePrincipal> itPrincipals = principals.iterator();
        while (itPrincipals.hasNext()) {
            RolePrincipal tempPrincipal = itPrincipals.next();
            Set permissionsFromTemplate = tempPrincipal.getAllPermissions();
            if (!globalPermissions.containsAll(permissionsFromTemplate)) {
                //we remove this principal which contains permissions not present in globalPermissions
                logger.warn(" principal called " + tempPrincipal.getLocalName() + " has been removed from the SubjectTemplate ");
                logger.warn(" because it contains permissions not owned by this organization throw its Principals ");
                itPrincipals.remove();
            }

        }
    }

    /**
     * Evaluate jexlExpression using UserPrincipal as context.<br>
     * and return <strong>true</strong> if expression is valid,
     * <strong>false</strong> otherwise.
     *
     * @param jexlExpression
     * @param userPrincipal
     * @return boolean
     */
    private static boolean evaluateDefinition(String jexlExpression, UserPrincipal userPrincipal) {
        final String PRIVATE_CREDENTIALS = "subject.privateCredentials";
        final String PUBLIC_CREDENTIALS = "subject.publicCredentials";
        final String ROLES = "subject.roles";
        final String ORGANIZATION = "subject.organization";
        if (jexlExpression == null) {
            return false;
        }
        if (Boolean.TRUE.toString().equalsIgnoreCase(jexlExpression)) {
            return true;
        }
        if (Boolean.FALSE.toString().equalsIgnoreCase(jexlExpression)) {
            return false;
        }
        if (userPrincipal == null) {
            logger.warn("evaluateDefinition() no UserPrincipal defined, can not use regex definition");
        }

        jexlExpression = jexlExpression.substring(2, jexlExpression.length() - 1);
        JexlContext jexlContext = JexlHelper.createContext();
        Map<String, Object> context = jexlContext.getVars();
        if (userPrincipal != null) {
            context.put(ORGANIZATION, userPrincipal.getOrganization());
            context.put(ROLES, userPrincipal.getRoles());
            context.put(PUBLIC_CREDENTIALS, userPrincipal.getPublicCredentials());
            context.put(PRIVATE_CREDENTIALS, userPrincipal.getPrivateCredentials());
        }


        Object resolvedExpression = null;
        try {
            Expression expression = ExpressionFactory.createExpression(jexlExpression);
            resolvedExpression = expression.evaluate(jexlContext);
        } catch (Exception e) {
            logger.warn("Failed to evaluate : " + jexlExpression);
        }

        if (!(resolvedExpression instanceof Boolean)) {
            logger.warn("Subject does not have the required credentials to resolve the role activation : " + jexlExpression);
            return false;
        } else {
            return (Boolean) resolvedExpression;
        }
    }

    /**
     * Evaluate principal definition attr and active attr.<br>
     * To resolve definition attr, this method uses a particular Principal (UserPrincipal)
     * set to the user during authentication. If this principal is not present and the definition attr != null, the
     * definition attr is not evaluated and the function returns false.
     * definition attr take precedence against active attr, so
     * if definition evaluate to false but active is true, then evaluatePrincipal return false
     *
     * @param ppal          RolePrincipal to evaluate
     * @param userPrincipal UserPrincipal used to evaluate ppal parameter
     * @return boolean
     */
    public static boolean evaluatePrincipal(RolePrincipal ppal, UserPrincipal userPrincipal) {
        if (!evaluateDefinition(ppal.getDefinition(), userPrincipal)) {
            if (logger.isDebugEnabled()) {
                logger.debug("evaluatePrincipal() -  user's principal definition attr evaluates to false=" + ppal.getLocalName());
            }
            return false;
        }
        if (!ppal.isActive()) {
            if (logger.isDebugEnabled()) {
                logger.debug("evaluatePrincipal() -  user's principal active attr is false=" + ppal.getLocalName());
            }
            return false;
        }
        return true;
    }

    /**
     * Resolve permission collection containing regular expressions.<br>
     * To resolve the permissions, this method uses a particular Principal (UserPrincipal)
     * set to the user during authentication. If this principal is not present, the
     * permission collection given in parameters is returned with no modifications. If
     * the UserPrincipal is present but does not contain the required data to resolved the regex,
     * the permission is removed from the permission collection.
     *
     * @param protectionDomain
     * @param pc
     * @return 
     */
    public static PermissionCollection evaluatePermissionCollection(ProtectionDomain protectionDomain, PermissionCollection pc) {
        final String PRIVATE_CREDENTIALS = "subject.privateCredentials";
        final String PUBLIC_CREDENTIALS = "subject.publicCredentials";
        final String SUBJECT_ROLES = "subject.roles";

        // resolve regular expressions in permissions
        Principal[] ppals = protectionDomain.getPrincipals();
        boolean hasJexlPrincipal = false;
        int i = 0;

        //we are looking for UserPrincipal to resolve regexp with JEXL
        while (!hasJexlPrincipal && i < ppals.length) {
            hasJexlPrincipal = ppals[i] instanceof UserPrincipal;
            i++;
        }
        PermissionCollection resolvedPc = new JGPositivePermissionCollection();

        
        if (!hasJexlPrincipal) {
            logger.debug("no UserPrincipal defined, can not use regex permissions");
            //we copy the pc content into the resolvedPc and return it
            Enumeration<Permission> e = pc.elements();
            while(e.hasMoreElements()){
                resolvedPc.add(e.nextElement());
            }
            return resolvedPc;
        } else {
            UserPrincipal subjectPrincipal = (UserPrincipal) ppals[i - 1];
            JexlContext jc = JexlHelper.createContext();
            Map<String, Map> vars = jc.getVars();
            vars.put(SUBJECT_ROLES, subjectPrincipal.getRoles());
            vars.put(PUBLIC_CREDENTIALS, subjectPrincipal.getPublicCredentials());
            vars.put(PRIVATE_CREDENTIALS, subjectPrincipal.getPrivateCredentials());

            //TODO CGA add time-based permissions with DurationDecorator class

            Enumeration permissionsEnum = pc.elements();

            Map<String, Object> subjectResolvedExpressions = new HashMap<String, Object>();
            // stores every already resolved expressions inside this method i.e. for a subject principal
            while (permissionsEnum.hasMoreElements()) {
                Permission permission = (Permission) permissionsEnum.nextElement();
                logger.debug("Resolving permission = " + permission);
                PermissionCollection pcFromPermission = PermissionUtils.resolvePermission(permission, subjectResolvedExpressions, jc);
                Enumeration<Permission> enumPermissions = pcFromPermission.elements();
                while (enumPermissions.hasMoreElements()) {
                    resolvedPc.add(enumPermissions.nextElement());
                }
            }

            return resolvedPc;
        }
    }


}
