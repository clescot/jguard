package net.sf.jguard.core.test;

import com.google.inject.Module;
import com.mycila.testing.junit.MycilaJunitRunner;
import net.sf.jguard.core.FilterChainModule;
import net.sf.jguard.core.authentication.AuthenticationModule;
import net.sf.jguard.core.authentication.AuthenticationScope;
import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import net.sf.jguard.core.authorization.AuthorizationModule;
import net.sf.jguard.core.authorization.AuthorizationScope;
import net.sf.jguard.core.authorization.manager.AuthorizationManager;
import org.junit.runner.RunWith;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Base class of JGuard tests, especially to initialize guice modules.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
@RunWith(MycilaJunitRunner.class)
public abstract class JGuardTest {

    protected static final String APPLICATION_NAME = JGuardTestFiles.JGUARD_STRUTS_EXAMPLE.getLabel();
    protected final URL authenticationXmlFileLocation = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_USERS_PRINCIPALS_XML.getLabel());


    public List<Module> providesModules(final AuthenticationScope authenticationScope,
                                        final boolean propagateThrowable,
                                        final URL applicationPath,
                                        final Class<? extends AuthorizationManager> authorizationManagerClass) {

        if (applicationPath == null) {
            throw new IllegalArgumentException("applicationPath must NOT be null");
        }
        if (authorizationManagerClass == null) {
            throw new IllegalArgumentException("authorizationManagerClass must NOT be null");
        }
        final URL filterConfigurationLocation = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_FILTER_XML.getLabel());
        if (filterConfigurationLocation == null) {
            throw new IllegalStateException("filterConfigurationLocation must NOT be null");
        }
        final URL authenticationConfigurationLocation = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_AUTHENTICATION_XML.getLabel());
        if (authenticationConfigurationLocation == null) {
            throw new IllegalStateException("authenticationConfigurationLocation must NOT be null");
        }
        final URL authorizationConfigurationLocation = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_AUTHORIZATION_XML.getLabel());
        if (authorizationConfigurationLocation == null) {
            throw new IllegalStateException("authorizationConfigurationLocation must NOT be null");
        }

        return new ArrayList<Module>() {{
            add(new FilterChainModule(
                    propagateThrowable
            ));
            add(new AuthenticationModule(
                    authenticationScope,
                    authenticationConfigurationLocation, filterConfigurationLocation));
            add(new AuthorizationModule(AuthorizationScope.LOCAL,
                    authorizationManagerClass,
                    authorizationConfigurationLocation,
                    applicationPath));
            add(buildAuthenticationManagerModule());
        }};
    }

    protected abstract AuthenticationManagerModule buildAuthenticationManagerModule();
}
