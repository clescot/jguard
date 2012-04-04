package net.sf.jguard.core.authentication.schemes;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HookImplFormSchemeHandler extends HookFormSchemeHandler {

    @Inject
    public HookImplFormSchemeHandler(Collection<Callback> callbacks) {
        super(callbacks);
    }
}
