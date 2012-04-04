package net.sf.jguard.ext.authorization.manager;

import com.google.inject.persist.Transactional;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.NegativePermissions;
import net.sf.jguard.core.PermissionResolutionCaching;
import net.sf.jguard.core.authorization.Permission;
import net.sf.jguard.core.authorization.manager.AuthorizationManagerException;
import net.sf.jguard.core.principals.RolePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import java.util.List;

/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.

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

public class JPAAuthorizationManager extends AbstractAuthorizationManager{

    private static final Logger logger = LoggerFactory.getLogger(JPAAuthorizationManager.class.getName());
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

   

    @Transactional
    public void createPermission(Permission permission) throws AuthorizationManagerException {
        EntityManager entityManager = entityManagerProvider.get();
        entityManager.persist(permission);
    }

    @Transactional
    public Permission readPermission(long permissionId) throws AuthorizationManagerException {
        EntityManager entityManager = entityManagerProvider.get();
        return entityManager.find(Permission.class,permissionId);
    }

    @Transactional
    public void updatePermission(Permission updatedPermission) throws AuthorizationManagerException {
        EntityManager entityManager = entityManagerProvider.get();
        entityManager.merge(updatedPermission);
    }

    @Transactional
    public void deletePermission(Permission permission) {
        EntityManager entityManager = entityManagerProvider.get();
        permission = entityManager.merge(permission);
        RolePrincipal rolePrincipal = permission.getRolePrincipal();
        if(rolePrincipal!=null){
            rolePrincipal.getPermissions().remove(permission);
        }
        entityManager.remove(permission);
    }

    @Transactional
    public void createPrincipal(RolePrincipal principal) throws AuthorizationManagerException {
       entityManagerProvider.get().persist(principal);
    }



    @Transactional
    public void deletePrincipal(RolePrincipal principal) throws AuthorizationManagerException {
        EntityManager entityManager = entityManagerProvider.get();
        RolePrincipal mergedPrincipal = entityManager.merge(principal);
        entityManager.remove(mergedPrincipal);

    }

    public boolean isEmpty() {
        EntityManager entityManager = entityManagerProvider.get();
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery<RolePrincipal> query = criteriaBuilder.createQuery(RolePrincipal.class);
        Root<RolePrincipal> from = query.from(RolePrincipal.class);
        CriteriaQuery<RolePrincipal> selectFrom = query.select(from);
        TypedQuery<RolePrincipal> typedQuery = entityManager.createQuery(selectFrom);
        int  principals= typedQuery.getResultList().size();


        CriteriaQuery<Permission> query2 = criteriaBuilder.createQuery(Permission.class);
        Root<Permission> from2 = query2.from(Permission.class);
        CriteriaQuery<Permission> selectFrom2 = query2.select(from2);
        TypedQuery<Permission> typedQuery2 = entityManager.createQuery(selectFrom2);
        int permissions = typedQuery2.getResultList().size();
        return !(principals == 0 && permissions == 0);

    }

     /**
     * return the corresponding application role.
     * @param roleId
     * @return role or null if not found
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager#readPrincipal(long)
     */
     @Transactional
    public RolePrincipal readPrincipal(long roleId) throws AuthorizationManagerException {
        EntityManager entityManager = entityManagerProvider.get();
        return entityManager.find(RolePrincipal.class,roleId);
    }


     /**
     * return the principal's Set.
     *
     * @return principal's Set
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager#listPrincipals()
     */
    public List<RolePrincipal> listPrincipals() {
        EntityManager entityManager = entityManagerProvider.get();
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery<RolePrincipal> rolePrincipalCriteriaQuery = criteriaBuilder.createQuery(RolePrincipal.class);
        Root<RolePrincipal> rootRolePrincipal = rolePrincipalCriteriaQuery.from(RolePrincipal.class);
        return entityManager.createQuery(rolePrincipalCriteriaQuery).getResultList();

    }

    /**
     * return all the permissions.
     *
     * @return URLPermission container
     */
    public List<Permission> listPermissions() {
        EntityManager entityManager = entityManagerProvider.get();
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Permission> permissionCriteriaQuery = criteriaBuilder.createQuery(Permission.class);
        Root<Permission> rootPermission = permissionCriteriaQuery.from(Permission.class);
        return entityManager.createQuery(permissionCriteriaQuery).getResultList();
    }

       /**
     * replace the inital principal with the new one.
     *
     * @param principal RolePrincipal updated
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     * @see net.sf.jguard.core.authorization.manager.AuthorizationManager
     */
    @Transactional
    public void updatePrincipal(RolePrincipal principal) throws AuthorizationManagerException {
        EntityManager entityManager = entityManagerProvider.get();
        entityManager.merge(principal);
        logger.debug(" updated principal=" + principal);
    }


/**
     * add the permission to the corresponding role.
     * if the permission is not persisted, we persist it and create
     * a corresponding Domain with the same name.
     *
     * @param roleId role updated
     * @param perm     permission to add
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException
     *
     */
    @Transactional
    public void addToPrincipal(long roleId, Permission perm) throws AuthorizationManagerException {
        EntityManager entityManager = entityManagerProvider.get();

        RolePrincipal principal = readPrincipal(roleId);
        principal.addPermission(perm);
        perm.setRolePrincipal(principal);
        entityManager.merge(perm);
        entityManager.merge(principal);
    }


   
}
