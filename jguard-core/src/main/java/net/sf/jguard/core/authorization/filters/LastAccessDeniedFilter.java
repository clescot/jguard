package net.sf.jguard.core.authorization.filters;


import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

/**
 * implemented by last access denied filters.
 *
 * @param <Req>
 * @param <Res>
 */
public interface LastAccessDeniedFilter<Req extends Request, Res extends Response> extends AuthorizationFilter<Req, Res> {
    String LAST_ACCESS_DENIED_PERMISSION = "lastAccessDeniedPermission";
}
