package net.sf.jguard.core.authorization;

import com.google.inject.Provider;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.core.authorization.policy.MultipleAppPolicy;

import javax.inject.Inject;

/**
 * Provides a {@link net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl} instance.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
class AccessControllerWrapperProvider implements Provider<AccessControllerWrapperImpl> {
    private AuthorizationScope authorizationScope;
    private MultipleAppPolicy policy;

    @Inject
    public AccessControllerWrapperProvider(AuthorizationScope authorizationScope, MultipleAppPolicy policy) {
        this.authorizationScope = authorizationScope;
        this.policy = policy;
    }

    public AccessControllerWrapperImpl get() {
        AccessControllerWrapperImpl accessControlWrapper;
        if (AuthorizationScope.JVM == authorizationScope) {
            accessControlWrapper = new AccessControllerWrapperImpl(null);
        } else {
            accessControlWrapper = new AccessControllerWrapperImpl(policy);
        }
        return accessControlWrapper;
    }
}
