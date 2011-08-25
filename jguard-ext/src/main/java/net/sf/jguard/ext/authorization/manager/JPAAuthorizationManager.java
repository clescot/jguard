package net.sf.jguard.ext.authorization.manager;

import com.google.inject.persist.PersistService;
import com.google.inject.persist.Transactional;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.NegativePermissions;
import net.sf.jguard.core.PermissionResolutionCaching;
import net.sf.jguard.core.authorization.manager.AuthorizationManagerException;
import net.sf.jguard.core.principals.RolePrincipal;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.security.Permission;
import java.security.Principal;
import java.util.List;
import java.util.Map;

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

public class JPAAuthorizationManager extends AbstractAuthorizationManager{


    private Provider<EntityManager> entityManagerProvider;

    /**
     * initialize AuthorizationManager implementation.
     * @param applicationName
     * @param negativePermissions true if permissions are negative, i.e, are interdictions.
     * @param permissionResolutionCaching true if a cache must be activated to boost performance
     * @param entityManagerProvider
     */
    @Inject
    public JPAAuthorizationManager(@ApplicationName String applicationName,
                                   @NegativePermissions boolean negativePermissions,
                                   @PermissionResolutionCaching boolean permissionResolutionCaching,
                                   Provider<EntityManager> entityManagerProvider
                                  ) {
        super(applicationName,negativePermissions,permissionResolutionCaching);
        this.entityManagerProvider = entityManagerProvider;
    }

    @Override
    public void refresh() {

    }

    public List getInitParameters() {
        return null;
    }

    public void createPermission(Permission url) throws AuthorizationManagerException {

    }

    public void updatePermission(String oldPermissionName, Permission updatedPermission) throws AuthorizationManagerException {

    }

    public void deletePermission(String permissionName) throws AuthorizationManagerException {

    }


    public void createPrincipal(Principal principal) throws AuthorizationManagerException {
       entityManagerProvider.get().persist(principal);
    }

    public void updatePrincipal(String oldPrincipalName, Principal principal) throws AuthorizationManagerException {

    }

    public void deletePrincipal(Principal principal) throws AuthorizationManagerException {

    }

    public boolean isEmpty() {
        return false;
    }

     /**
     * return the corresponding application role.
     * @param localName role name: it does not contains the application Name, because the authorization part
      * of jguard is shared amongst one application. only the authentication part is across multiple application
      * storing, for each application, roles owned by each users. the authenitcation part store the application name
      * to avoid any role names conflict between applications.
     * @return role or null if not found
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager#readPrincipal(java.lang.String)
     */
     @Transactional
    public Principal readPrincipal(String localName) throws AuthorizationManagerException {
        EntityManager entityManager = entityManagerProvider.get();
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery<RolePrincipal> query = criteriaBuilder.createQuery(RolePrincipal.class);
        Root<RolePrincipal> from = query.from(RolePrincipal.class);
        CriteriaQuery<RolePrincipal> selectFrom = query.select(from);
        Predicate where = criteriaBuilder.equal(from.get("localName"),localName);
        CriteriaQuery<RolePrincipal> selectFromWhere = selectFrom.where(where);
        TypedQuery<RolePrincipal> typedQuery = entityManager.createQuery(selectFromWhere);
        return typedQuery.getSingleResult();
    }

   
}
