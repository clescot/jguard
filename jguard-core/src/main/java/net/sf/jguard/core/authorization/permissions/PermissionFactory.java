package net.sf.jguard.core.authorization.permissions;

import net.sf.jguard.core.lifecycle.Request;

import java.security.Permission;

/**
 * return a Permission from a request.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public interface PermissionFactory<Req> {

    Permission getPermission(Request<Req> request);

}
