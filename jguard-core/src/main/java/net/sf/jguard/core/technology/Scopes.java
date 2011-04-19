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


package net.sf.jguard.core.technology;


/**
 * Authentication bindings with the underlying protocol and server technology
 * used by the  PolicyEnforcementPoint.
 * Note that implementation of this interface <strong>DOES NOT</strong>
 * authenticate any entity.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @see net.sf.jguard.core.enforcement.PolicyEnforcementPoint
 * @see net.sf.jguard.core.authentication.AbstractAuthenticationServicePoint
 * @since 2.0
 */
public interface Scopes {


    //request specific method

    void setRequestAttribute(String key, Object value);

    Object getRequestAttribute(String key);

    void removeRequestAttribute(String key);


    //application specific method

    void setApplicationAttribute(String key, Object value);

    Object getApplicationAttribute(String key);

    void removeApplicationAttribute(String key);

    /**
     * parameter defined for initialization purpose, reachable
     * at an application scope.
     *
     * @param key
     * @return value as a String
     */
    String getInitApplicationAttribute(String key);


}
