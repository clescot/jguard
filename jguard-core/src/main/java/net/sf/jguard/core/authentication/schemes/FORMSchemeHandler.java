package net.sf.jguard.core.authentication.schemes;

import javax.inject.Inject;
import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.authorization.permissions.PermissionFactory;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.security.auth.callback.Callback;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Collection;
import java.util.Map;

/**
 * grab informations from a FORM to permit authentication.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public abstract class FORMSchemeHandler<Req, Res> implements StatefulAuthenticationSchemeHandler<Req, Res> {

    Collection<Class<? extends Callback>> callbackTypes = null;
    private PermissionCollection grantedPermissions;
    protected Permission logoffPermission;
    protected Permission logonPermission;
    protected Permission logonProcessPermission;
    protected StatefulScopes authenticationBindings;
    protected boolean goToLastAccessDeniedUriOnSuccess = true;
    private static final String GO_TO_LAST_ACCESS_DENIED_URI_ON_SUCCESS = "goToLastAccessDeniedUriOnSuccess";

    @Inject
    public FORMSchemeHandler(Map<String, String> parameters, StatefulScopes authenticationBindings) {
        super();
        this.authenticationBindings = authenticationBindings;
        this.goToLastAccessDeniedUriOnSuccess = Boolean.parseBoolean(parameters.get(GO_TO_LAST_ACCESS_DENIED_URI_ON_SUCCESS));
    }

    protected void buildGrantedPermissions() {
        grantedPermissions = new JGPositivePermissionCollection();
        grantedPermissions.add(getLogonPermission());
        grantedPermissions.add(getLogoffPermission());
        grantedPermissions.add(getLogonProcessPermission());
    }


    public boolean answerToChallenge(Request<Req> request, Response<Res> response) {
        return getLogonProcessPermission().implies(getPermissionFactory().getPermission(request));
    }

    public boolean challengeNeeded(Request<Req> request, Response<Res> response) {
        return true;
    }

    public PermissionCollection getGrantedPermissions() {
        return grantedPermissions;
    }

    public Collection<Class<? extends Callback>> getCallbackTypes() {
        return callbackTypes;
    }


    /**
     * @return Permission bound to the FORM target.
     */
    protected abstract Permission getLogonProcessPermission();


    public abstract Permission getLogoffPermission();

    public abstract Permission getLogonPermission();


    /**
     * return the PermissionFactory.
     *
     * @return
     */
    protected abstract PermissionFactory<Req> getPermissionFactory();


}
