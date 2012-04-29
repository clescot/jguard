package net.sf.jguard.jee.authentication.http;

import net.sf.jguard.core.authentication.schemes.HookFormSchemeHandler;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletHookFormSchemeHandler extends HookFormSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter> {

    @Inject
    public HttpServletHookFormSchemeHandler(Collection<Callback> callbacks) {
        super(callbacks);
    }
}
