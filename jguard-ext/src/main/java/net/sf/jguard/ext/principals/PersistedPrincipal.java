/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
package net.sf.jguard.ext.principals;

import net.sf.jguard.core.principals.BasePrincipal;

/**
* Persistent view of a principal.
* @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
*/
public class PersistedPrincipal implements BasePrincipal{

    
    private Long id;
    private String className;
    private String applicationName;
    private String name;
    private Long organizationId;

    public PersistedPrincipal(){
        
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

       
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int compareTo(Object o) {
        PersistedPrincipal principal = (PersistedPrincipal)o;
        if (this.equals(o)){
            return 0;
        }
        return this.getName().compareTo(principal.getName());
        
    }
    
    public Object clone()throws CloneNotSupportedException{
        PersistedPrincipal principal = (PersistedPrincipal) super.clone();
        principal.setName(this.getName());
        principal.setClassName(this.getClassName());
        principal.setApplicationName(this.getApplicationName());
        return principal;
    }

    public int hashCode() {
        int hash = 5;
        hash = 23 * hash + (this.className != null ? this.className.hashCode() : 0);
        hash = 23 * hash + (this.applicationName != null ? this.applicationName.hashCode() : 0);
        hash = 23 * hash + (this.name != null ? this.name.hashCode() : 0);
        return hash;
    }
    
     public boolean equals(Object other) {
         if (this == other){
             return true;
         }
         if ( !(other instanceof PersistedPrincipal) ){
              return false;
         }
         
         final PersistedPrincipal pprincpal = (PersistedPrincipal)other;
         return name.equals(pprincpal.getName()) &&
                 className.equals(pprincpal.getClassName())
                 && applicationName.equals(pprincpal.getApplicationName());
     }

    public Long getOrganizationId() {
        return organizationId;
    }

    public void setOrganizationId(Long organizationId) {
        this.organizationId = organizationId;
    }
}
