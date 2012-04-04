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
package net.sf.jguard.core.authorization.permissions;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheException;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;
import org.apache.commons.jexl.Expression;
import org.apache.commons.jexl.ExpressionFactory;
import org.apache.commons.jexl.JexlContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * java.security.Permission related utility class.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
public final class PermissionUtils {

    private static final Logger logger = LoggerFactory.getLogger(PermissionUtils.class.getName());

    private static CacheManager manager;
    private static Cache unresolvedPermToNeededExpressions;
    private static Cache unresolvedPermAndValuesToResolvedPerm;
    private static boolean cachesEnabled;
    private static final Pattern JEXL_PATTERN = Pattern.compile("(\\$\\{[^\\}]+\\})");


    private PermissionUtils() {

    }


    private static Set createKey(Permission unresolvedPermission, Map<String, Object> values) {

        Set key = new HashSet();
        key.add(unresolvedPermission);
        key.add(values);

        return key;
    }

    /**
     * return all the permissions which match the regexp expression present in the
     * permission passed as a parameter.
     *
     * @param permission                 to resolve
     * @param subjectResolvedExpressions Map containing JEXL expression as <strong>key</strong>, and Resolved Permission as <strong>value</strong>
     * @param jexlContext                JEXL context containing variables used to resolve permissions.
     * @return resolved PermissionCollection
     */
    public static PermissionCollection resolvePermission(Permission permission, Map<String, Object> subjectResolvedExpressions, JexlContext jexlContext) {

        PermissionCollection resolvedPermissions = new JGPositivePermissionCollection();

        // try to get the resolved permissions from the cache
        if (cachesEnabled) {
            try {
                // check in cache if unresolved permission -> needed expressions exists
                Element expressionsCacheEntry = unresolvedPermToNeededExpressions.get(permission);
                if (expressionsCacheEntry != null) {

                    Set neededExpressions = (Set) expressionsCacheEntry.getValue();

                    if (neededExpressions.isEmpty()) {
                        // no need to resolve this permission
                        resolvedPermissions.add(permission);
                        logger.debug("get permission from cache with no resolution needed");
                        return resolvedPermissions;
                    }

                    Iterator itExpressions = neededExpressions.iterator();
                    Map<String, Object> permissionResolvedExpressions = new HashMap<String, Object>();
                    boolean hasNull = false;
                    while (itExpressions.hasNext()) {
                        String jexlExpression = (String) itExpressions.next();
                        Object resolvedExpression = null;

                        if (subjectResolvedExpressions.containsKey(jexlExpression)) {
                            resolvedExpression = subjectResolvedExpressions.get(jexlExpression);
                            permissionResolvedExpressions.put(jexlExpression, resolvedExpression);
                        } else {
                            try {
                                Expression expression = ExpressionFactory.createExpression(jexlExpression);
                                //resolution work made by JEXL is done here
                                resolvedExpression = expression.evaluate(jexlContext);
                                subjectResolvedExpressions.put(jexlExpression, resolvedExpression);
                                permissionResolvedExpressions.put(jexlExpression, resolvedExpression);
                            } catch (Exception e) {
                                logger.warn("Failed to evaluate : " + jexlExpression);
                            }
                        }

                        if (resolvedExpression == null || (resolvedExpression instanceof List && ((List) resolvedExpression).isEmpty())) {
                            hasNull = true;
                            break;
                        }

                    }

                    if (hasNull) {
                        logger.warn("Subject does not have the required credentials to resolve the permission : " + permission);
                        //skip this unresolvable permission
                        resolvedPermissions.add(permission);
                        return resolvedPermissions;
                    }

                    // check in cache if (needed values + unresolvedPermission) -> resolved permission exists
                    Set key = createKey(permission, permissionResolvedExpressions);
                    Element permissionCacheEntry = unresolvedPermAndValuesToResolvedPerm.get(key);

                    if (permissionCacheEntry != null) {
                        PermissionCollection permissionsFromCache = (PermissionCollection) permissionCacheEntry.getValue();
                        logger.debug("get resolved permission from cache");
                        Enumeration enumeration = permissionsFromCache.elements();
                        while (enumeration.hasMoreElements()) {
                            Permission permissionFromCache = (Permission) enumeration.nextElement();
                            resolvedPermissions.add(permissionFromCache);
                        }
                        return resolvedPermissions;
                    }
                }
            } catch (CacheException e) {
                logger.warn("Failed using caches : " + e.getMessage());
            }
        }

        // if permission is not yet resolved continue
        // resolution will be fast because jexlExpression -> value
        // has already been resolved and stored in resolvedValues

        // resolution is combinative so one unresolved permission
        // may imply n resolved permissions
        List<Permission> unresolvedPermissions = new ArrayList<Permission>();
        unresolvedPermissions.add(permission);
        Map resolvedExpressionsByPermission = new HashMap();

        while (!unresolvedPermissions.isEmpty()) {

            Permission unresolvedPermission = unresolvedPermissions.remove(0);

            String name = unresolvedPermission.getName();
            Set partiallyResolvedNames = resolvePartiallyExpression(name, JEXL_PATTERN, jexlContext, resolvedExpressionsByPermission, subjectResolvedExpressions);
            if (partiallyResolvedNames == null) {
                // unresolvable permission
                return new JGPositivePermissionCollection();
            }

            boolean matchesInName = (partiallyResolvedNames.size() != 1 || !partiallyResolvedNames.contains(name));
            if (matchesInName) {
                for (Object partiallyResolvedName : partiallyResolvedNames) {
                    String resolvedName = (String) partiallyResolvedName;
                    Permission partiallyResolvedPermission;
                    try {
                        partiallyResolvedPermission = net.sf.jguard.core.authorization.Permission.getPermission(permission.getClass(), resolvedName, unresolvedPermission.getActions());
                    } catch (ClassNotFoundException e) {
                        logger.warn(e.getMessage());
                        continue;
                    }
                    unresolvedPermissions.add(partiallyResolvedPermission);
                }
                continue;
            }

            String actions = unresolvedPermission.getActions();
            if (actions == null) {
                actions = "";
            }
            String[] actionsArray = actions.split(",");
            String action = actionsArray[0];
            Set partiallyResolvedActions = resolvePartiallyExpression(action, JEXL_PATTERN, jexlContext, resolvedExpressionsByPermission, subjectResolvedExpressions);
            if (partiallyResolvedActions == null) {
                // unresolvable permission
                return new JGPositivePermissionCollection();
            }

            boolean matchesInActions = (partiallyResolvedActions.size() != 1 || !partiallyResolvedActions.contains(action));
            if (matchesInActions) {
                for (Object partiallyResolvedAction : partiallyResolvedActions) {
                    String resolvedAction = (String) partiallyResolvedAction;
                    Permission partiallyResolvedPermission;
                    try {
                        partiallyResolvedPermission = net.sf.jguard.core.authorization.Permission.getPermission(permission.getClass(), unresolvedPermission.getName(), resolvedAction);
                    } catch (ClassNotFoundException e) {
                        logger.warn(e.getMessage());
                        continue;
                    }
                    unresolvedPermissions.add(partiallyResolvedPermission);
                }
                continue;
            }

            // if this code is reached, there is no match in name and actions
            // the permission is resolved
            resolvedPermissions.add(unresolvedPermission);
        }

        if (cachesEnabled) {
            try {
                // store permissions needed expressions in cache
                if (!unresolvedPermToNeededExpressions.isKeyInCache(permission)) {

                    HashSet permissionNeededExpressions = new HashSet(resolvedExpressionsByPermission.keySet());
                    unresolvedPermToNeededExpressions.put(new Element(permission, permissionNeededExpressions));
                }
            } catch (CacheException e) {
                logger.warn("Failed using caches : " + e.getMessage());
            }

            // store mapping (values + unresolved permission ) -> resolved permission in cache
            Element cacheEntry = new Element(createKey(permission, resolvedExpressionsByPermission), resolvedPermissions);
            unresolvedPermAndValuesToResolvedPerm.put(cacheEntry);
            logger.debug("add resolved permissions to cache");
        }

        return resolvedPermissions;
    }


    /**
     * /**
     * resolves first occurence of jexl expression. The other expressions remain unresolved
     *
     * @param expression
     * @param pattern
     * @param jexlContext
     * @param resolvedExpressionsByPermission
     *
     * @param subjectResolvedExpressions
     * @return
     */
    private static Set resolvePartiallyExpression(String expression,
                                                  Pattern pattern,
                                                  JexlContext jexlContext,
                                                  Map<String, Object> resolvedExpressionsByPermission,
                                                  Map<String, Object> subjectResolvedExpressions) {

        boolean hasMatches = false;
        boolean hasNull = false;

        Set<String> resolvedExpressionsSet = new HashSet<String>();

        Matcher matcher = pattern.matcher(expression);
        if (matcher.find()) {
            hasMatches = true;
            String matchedExpression = matcher.group();

            String jexlExpression = matchedExpression.substring(2, matchedExpression.length() - 1);
            Object resolvedExpression = null;

            if (subjectResolvedExpressions.containsKey(jexlExpression)) {
                resolvedExpression = subjectResolvedExpressions.get(jexlExpression);
            } else {
                try {
                    Expression expr = ExpressionFactory.createExpression(jexlExpression);
                    resolvedExpression = expr.evaluate(jexlContext);
                    subjectResolvedExpressions.put(jexlExpression, resolvedExpression);

                } catch (Exception e) {
                    logger.warn("Failed to resolve expression : " + jexlExpression);
                }
            }

            if (!(resolvedExpressionsByPermission.containsKey(jexlExpression))) {
                resolvedExpressionsByPermission.put(jexlExpression, resolvedExpression);
            }

            if (resolvedExpression == null) {
                // expression can not be resolved
                hasNull = true;
            } else if (resolvedExpression instanceof Set) {
                for (Object o : ((Set) resolvedExpression)) {
                    StringBuffer builder = new StringBuffer(expression);
                    builder.replace(matcher.start(), matcher.end(), (String) o);
                    resolvedExpressionsSet.add(builder.toString());
                }
            } else if (resolvedExpression instanceof String) {
                StringBuffer builder = new StringBuffer(expression);
                builder.replace(matcher.start(), matcher.end(), (String) resolvedExpression);
                resolvedExpressionsSet.add(builder.toString());
            }
        }

        if (!hasMatches) {
            // no jexl expression in part, return original part
            resolvedExpressionsSet.add(expression);
        }
        if (hasNull) {
            // can not be resolved
            return null;
        }

        return resolvedExpressionsSet;
    }

    public static void createCaches() throws CacheException {
        // gets ehcache.xml as a resource in the classpath
        if (unresolvedPermToNeededExpressions == null ||
                unresolvedPermAndValuesToResolvedPerm == null) {
            logger.info("Creating caches for permissions evaluations");
            manager = CacheManager.create();
            unresolvedPermToNeededExpressions = manager.getCache("unresolvedPermToNeededExpressions");
            unresolvedPermAndValuesToResolvedPerm = manager.getCache("unresolvedPermAndValuesToResolvedPerm");

            if (unresolvedPermToNeededExpressions == null || unresolvedPermAndValuesToResolvedPerm == null) {
                logger.warn("Failed to create caches for permissions evaluations, use non-caching evaluation");
                PermissionUtils.cachesEnabled = false;
            } else {
                PermissionUtils.cachesEnabled = true;
            }
        }
        PermissionUtils.cachesEnabled = true;
    }

    public static boolean isCachesEnabled() {
        return cachesEnabled;
    }


    public static void setCachesEnabled(boolean cachesEnabled) {
        PermissionUtils.cachesEnabled = cachesEnabled;
    }

    /**
     * create an heterogenous PermissionCollection( formerly, a Permission<b>s<b/> instance
     * which will contains the content of the two PermissionCollections.
     *
     * @param perm1
     * @param perm2
     * @return
     */
    public static Permissions mergePermissionCollections(PermissionCollection perm1, PermissionCollection perm2) {
        Permissions result = new Permissions();
        addPermissionCollectionToPermissions(result, perm1);
        addPermissionCollectionToPermissions(result, perm2);
        return result;
    }

    /**
     * add Permission instance from the PermissionCollection to the Heterogeneous Permissions instance.
     *
     * @param permissions
     * @param collection
     */
    private static void addPermissionCollectionToPermissions(Permissions permissions, PermissionCollection collection) {
        if (collection == null || permissions == null) {
            return;
        }
        Enumeration enumPerm = collection.elements();
        while (enumPerm.hasMoreElements()) {
            Permission perm = (Permission) enumPerm.nextElement();
            permissions.add(perm);
        }
    }

    
}