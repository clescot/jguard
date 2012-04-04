package net.sf.jguard.jee.authentication.http;

import net.sf.jguard.core.authentication.schemes.HookFormSchemeHandler;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletHookFormSchemeHandler extends HookFormSchemeHandler<HttpServletRequest, HttpServletResponse> {

    @Inject
    public HttpServletHookFormSchemeHandler(Collection<Callback> callbacks) {
        super(callbacks);
    }
}
