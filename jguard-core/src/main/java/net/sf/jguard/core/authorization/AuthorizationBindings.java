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

import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import java.security.Permission;


/**
 * encode and decode authorization informations into the underlying protocol.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public interface AuthorizationBindings<Req, Res> {
    /**
     * extract from the Request the authorization informations as a Permission.
     *
     * @param request
     * @return
     */
    Permission getPermissionRequested(Request<Req> request);


    /**
     * return the post authentication Permission to follow after a successful authentication.
     * note that it can be overriden by the lastAccessDeniedPermission.
     *
     * @param request
     * @return
     */
    Permission getPostAuthenticationPermission(Request<Req> request);

    /**
     * translate into the underlying technology the access denied event.
     *
     * @param request
     * @param response
     */
    void accessDenied(Request<Req> request, Response<Res> response);

    /**
     * translate into the request or the response the permission to follow.
     *
     * @param request
     * @param response
     * @param permission
     */
    void handlePermission(Request<Req> request, Response<Res> response, Permission permission);

}
