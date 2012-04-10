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
package net.sf.jguard.core.authentication.credentials;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class which wrap security credential.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class JGuardCredential implements Serializable, Cloneable {

    //TODO may implements Refreshable and Destroyable interfaces
    // cf http://java.sun.com/security/jaas/doc/api.html
    private static final long serialVersionUID = 2251806339749583892L;
    private transient Logger logger = Logger.getLogger(JGuardCredential.class.getName());
    private String name = null;
    private Object value = null;
    private Long id;
    private boolean publicVisibility;
    private static final String CLONE = "clone";

    /**
     * present only for persistence.
     * we restrict its access to package private.
     */
    JGuardCredential() {
    }

    public JGuardCredential(String name, Object value) {
        this.name = name;
        this.value = value;
    }


    /**
     * @return Returns the id.
     */
    public String getName() {
        return name;
    }

    /**
     * present only for persistence.
     * we restrict its access to package private.
     *
     * @param id The id to set.
     */
    void setName(String id) {
        this.name = id;
    }

    /**
     * @return Returns the value.
     */
    public Object getValue() {
        return value;
    }

    /**
     * @param value The value to set.
     */
    void setValue(Object value) {
        this.value = value;
    }

    /**
     * used to compare an object to this credential.
     *
     * @param obj object to compare
     * @return <i>true</i> if equals, <i>false</i> otherwise
     */
    public boolean equals(Object obj) {
        JGuardCredential cred;
        if (obj instanceof JGuardCredential) {
            cred = (JGuardCredential) obj;
        } else {
            return false;
        }
        return this.name.equals(cred.name) && this.value.equals(cred.value);
    }


    public int hashCode() {
        if (name != null && value != null) {
            return name.hashCode() + value.hashCode();
        } else if (value == null && name != null) {
            return name.hashCode();
        } else {
            return -1;
        }
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("\n");
        sb.append("id=");
        sb.append(name);
        sb.append("\n");
        sb.append("value=");
        sb.append(value);
        sb.append("\n");
        sb.append("identity=");
        sb.append("\n");
        return sb.toString();
    }

    /**
     * we ignore PMD.PreserveStackTrace violation due to the bad design of CloneNotSupportedException
     * constructor.
     *
     * @return
     * @throws CloneNotSupportedException
     */
    @SuppressWarnings("PMD.PreserveStackTrace")
    @Override
    public Object clone() throws CloneNotSupportedException {
        JGuardCredential clone = (JGuardCredential) super.clone();
        clone.setId(null);
        clone.setName(name);
        if (value == null) {
            clone.setValue(null);
            return clone;
        }
        if (value instanceof Cloneable) {
            Class[] clazz = new Class[]{};
            try {
                Method cloneMethod = value.getClass().getMethod(CLONE, clazz);
                Object clonedValue = cloneMethod.invoke(value, null);
                clone.setValue(clonedValue);
            } catch (SecurityException e) {
                logger.log(Level.SEVERE, e.getMessage(), e);
                throw new CloneNotSupportedException(e.getMessage());
            } catch (NoSuchMethodException e) {
                logger.log(Level.SEVERE, e.getMessage(), e);
                throw new CloneNotSupportedException(e.getMessage());
            } catch (IllegalArgumentException e) {
                logger.log(Level.SEVERE, e.getMessage(), e);
                throw new CloneNotSupportedException(e.getMessage());
            } catch (IllegalAccessException e) {
                logger.log(Level.SEVERE, e.getMessage(), e);
                throw new CloneNotSupportedException(e.getMessage());
            } catch (InvocationTargetException e) {
                logger.log(Level.SEVERE, e.getMessage(), e);
                throw new CloneNotSupportedException(e.getMessage());
            }


        } else if (value instanceof String) {
            clone.setValue(value);
        } else {

            throw new CloneNotSupportedException(value.getClass() + " does not support cloning mechanism ");
        }

        return clone;
    }

    public static Set<JGuardCredential> cloneCredentialsSet(Set<JGuardCredential> credentials) throws CloneNotSupportedException {
        Set<JGuardCredential> clonedCredentials = new HashSet<JGuardCredential>();
        for (JGuardCredential credential : credentials) {
            clonedCredentials.add((JGuardCredential) credential.clone());
        }
        return clonedCredentials;
    }

    public Long getId() {
        return id;
    }

    /**
     * only present for persistence.
     * we restrict its access to package private.
     *
     * @param id
     */
    void setId(Long id) {
        this.id = id;
    }

    public boolean isPublicVisibility() {
        return publicVisibility;
    }

    /**
     * only present for persistence.
     * we restrict its access to package private.
     *
     * @param publicVisibility
     */
    void setPublicVisibility(boolean publicVisibility) {
        this.publicVisibility = publicVisibility;
    }
}
