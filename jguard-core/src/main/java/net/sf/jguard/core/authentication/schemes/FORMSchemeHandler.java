package net.sf.jguard.core.authentication.schemes;

import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.authorization.permissions.PermissionFactory;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Collection;
import java.util.Map;

/**
 * grab informations from a FORM to permit authentication.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class FORMSchemeHandler<Req extends Request, Res extends Response> implements StatefulAuthenticationSchemeHandler<Req, Res> {

    Collection<Class<? extends Callback>> callbackTypes = null;
    private PermissionCollection grantedPermissions;
    protected Permission logoffPermission;
    protected Permission logonPermission;
    protected Permission logonProcessPermission;
    protected StatefulScopes statefulScopes;
    protected boolean goToLastAccessDeniedUriOnSuccess = true;
    private static final String GO_TO_LAST_ACCESS_DENIED_URI_ON_SUCCESS = "goToLastAccessDeniedUriOnSuccess";

    @Inject
    public FORMSchemeHandler(Map<String, String> parameters, StatefulScopes statefulScopes) {
        super();
        this.statefulScopes = statefulScopes;
        this.goToLastAccessDeniedUriOnSuccess = Boolean.parseBoolean(parameters.get(GO_TO_LAST_ACCESS_DENIED_URI_ON_SUCCESS));
    }

    protected void buildGrantedPermissions() {
        grantedPermissions = new JGPositivePermissionCollection();
        grantedPermissions.add(getLogonPermission());
        grantedPermissions.add(getLogoffPermission());
        grantedPermissions.add(getLogonProcessPermission());
    }


    public boolean answerToChallenge(Req request, Res response) {
        return getLogonProcessPermission().implies(getPermissionFactory().getPermission(request));
    }

    public boolean challengeNeeded(Req request, Res response) {
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
