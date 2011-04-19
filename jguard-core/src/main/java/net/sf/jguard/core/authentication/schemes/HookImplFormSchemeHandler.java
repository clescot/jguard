package net.sf.jguard.core.authentication.schemes;

import com.google.inject.Inject;

import javax.security.auth.callback.Callback;
import java.util.Collection;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class HookImplFormSchemeHandler extends HookFormSchemeHandler {

    @Inject
    public HookImplFormSchemeHandler(Collection<Callback> callbacks) {
        super(callbacks);
    }
}
