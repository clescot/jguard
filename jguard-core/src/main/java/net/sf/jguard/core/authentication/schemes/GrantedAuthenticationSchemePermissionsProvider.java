package net.sf.jguard.core.authentication.schemes;

import com.google.inject.Provider;

import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.util.Collection;
import java.util.Enumeration;

/**
 * return {@link Permissions} which must be granted by the {@link java.security.Policy},
 * according to the {@link net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler} list.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class GrantedAuthenticationSchemePermissionsProvider<Req, Res> implements Provider<Permissions> {
    private Collection<AuthenticationSchemeHandler<Req, Res>> authenticationSchemeHandlers;


    public GrantedAuthenticationSchemePermissionsProvider(Collection<AuthenticationSchemeHandler<Req, Res>> authenticationSchemeHandlers) {
        this.authenticationSchemeHandlers = authenticationSchemeHandlers;
    }


    public Permissions get() {
        Permissions alwaysGrantedPermissions = new Permissions();
        for (AuthenticationSchemeHandler authHandler : authenticationSchemeHandlers) {
            PermissionCollection permColl = authHandler.getGrantedPermissions();
            Enumeration<Permission> perms = permColl.elements();
            while (perms.hasMoreElements()) {
                alwaysGrantedPermissions.add(perms.nextElement());
            }
        }
        return alwaysGrantedPermissions;
    }
}
