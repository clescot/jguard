package net.sf.jguard.core.authorization.filters;


/**
 * implemented by last access denied filters.
 *
 * @param <Req>
 * @param <Res>
 */
public interface LastAccessDeniedFilter<Req, Res> extends AuthorizationFilter<Req, Res> {
    String LAST_ACCESS_DENIED_PERMISSION = "lastAccessDeniedPermission";
}
