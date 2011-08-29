/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
package net.sf.jguard.core.authorization;

import net.sf.jguard.core.principals.RolePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.persistence.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.BasicPermission;
import java.util.Collection;
import java.util.HashSet;

/**
* POJO counterpart of {@link java.security.Permission}.
* @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
*/
@Entity
@Table(name = "jg_permission")
public class Permission {



    private static final Logger logger = LoggerFactory.getLogger(Permission.class.getName());


    @Id @GeneratedValue
    private long id;

    private String name;

    private String actions;

    private String clazz;

    @ManyToOne
    @JoinColumn(nullable = true)
    private RolePrincipal rolePrincipal;
    
    public Permission(){
        
    }

    public Permission(Class clazz, String name,String actions){
        this.clazz = clazz.getName();
        this.name = name;
        this.actions = actions;
    }

    /**
     * instantiate a java.security.Permission subclass.
     *
     * @param clazz class name
     * @param name      permission name
     * @param actions   actions name split by comma ','
     * @return a java.security.Permission subclass, or a java.security.BasicPermission subclass
     *         (which inherit java.security.Permission)
     * @throws ClassNotFoundException
     */
    public static java.security.Permission getPermission(Class clazz, String name, String actions) throws ClassNotFoundException {
        if(!java.security.Permission.class.isAssignableFrom(clazz)){
            throw new IllegalArgumentException("clazz["+clazz.getName()+"] is not a subclass of java.security.Permission");
        }
        String className = clazz.getName();
      
        Class[] permArgsBasicPermClass = {String.class, String.class};
        Class[] permArgsPermClass = {String.class};
        Object[] objBasicArray = {name, actions};
        java.security.Permission newPerm = null;
        try {
            //check if className inherit from the Abstract BasicPermission class which
            // has got a two string argument constructor to speed up the lookup
            if (clazz.isAssignableFrom(BasicPermission.class)) {
                newPerm = (java.security.Permission) clazz.getConstructor(permArgsBasicPermClass).newInstance(objBasicArray);
                return newPerm;
            }

            Object[] objArray = {name};

            Constructor[] constructors = clazz.getConstructors();
            boolean constructorWithActions = false;
            for (Constructor tempConstructor : constructors) {
                Class[] classes = tempConstructor.getParameterTypes();
                if (classes.length == 2 && classes[0].equals(String.class) && classes[1].equals(String.class) && !"".equals(objBasicArray[1])) {
                    constructorWithActions = true;
                    break;
                }
            }

            // a class which does not inherit from BasicPermission but has got a two string arguments constructor
            if (constructorWithActions) {
                newPerm = (java.security.Permission) clazz.getConstructor(permArgsBasicPermClass).newInstance(objBasicArray);
            } else {
                //Permission subclass which has got a constructor with name argument
                newPerm = (java.security.Permission) clazz.getConstructor(permArgsPermClass).newInstance(objArray);
            }
        } catch (IllegalArgumentException e) {
            logger.error(" illegal argument ", e);
        } catch (SecurityException e) {
            logger.error("className=" + className);
            logger.error("name=" + name);
            logger.error("actions=" + actions);
            logger.error(" you don't have right to instantiate a permission ", e);
        } catch (InstantiationException e) {
            logger.error("className=" + className);
            logger.error("name=" + name);
            logger.error("actions=" + actions);
            logger.error(" you cannot instantiate a permission ", e);
        } catch (IllegalAccessException e) {
            logger.error("className=" + className);
            logger.error("name=" + name);
            logger.error("actions=" + actions);
            logger.error(e.getMessage(), e);
        } catch (InvocationTargetException e) {
            logger.error("className=" + className);
            logger.error("name=" + name);
            logger.error("actions=" + actions);
            logger.error(e.getMessage(), e);
        } catch (NoSuchMethodException e) {
            logger.error("method not found =", e);
        }
        return newPerm;
    }

    public java.security.Permission toJavaPermission()  {
        try {
            Class cl = Thread.currentThread().getContextClassLoader().loadClass(clazz);
            return getPermission(cl,this.getName(),this.getActions());
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static Permission translateToJGuardPermission(java.security.Permission permission){
        return new Permission(permission.getClass(),permission.getName(),permission.getActions());
    }

    public static Collection<Permission> translateToJGuardPermissions(Collection<java.security.Permission> permissions){
        Collection<Permission> jguardPermissions = new HashSet<Permission>();
        for(java.security.Permission permission:permissions){
            jguardPermissions.add(translateToJGuardPermission(permission));
        }

        return jguardPermissions;
    }

    public static Collection<java.security.Permission> translateToJavaPermissions(Collection<Permission> permissionColl) {
        Collection<java.security.Permission> permissions = new HashSet<java.security.Permission>();
        for (Permission permission:permissionColl){
                permissions.add(permission.toJavaPermission());
        }
        return permissions;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getActions() {
        return actions;
    }

    public void setActions(String actions) {
        this.actions = actions;
    }

    public String getClazz() {
        return clazz;
    }

    public void setClazz(String clazz) {
        this.clazz = clazz;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }


    public int hashCode(){
        if(clazz==null||name==null||actions==null){
            return 4;
        }else{
            return clazz.hashCode()+name.hashCode()+actions.hashCode();
        }
    }

    public boolean equals(Object object){
        if (!Permission.class.isAssignableFrom(object.getClass())){
            return false;
        }else{
            Permission permission = (Permission)object;
            return this.getClazz().equals(permission.getClazz())
                    && this.getName().equals(permission.getName())
                    && this.getActions().equals(permission.getActions());
        }
    }
}
