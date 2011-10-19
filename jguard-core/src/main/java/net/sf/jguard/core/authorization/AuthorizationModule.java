package net.sf.jguard.core.authorization;

import com.google.inject.AbstractModule;
import com.google.inject.Singleton;
import com.google.inject.TypeLiteral;
import net.sf.jguard.core.*;
import net.sf.jguard.core.authorization.manager.*;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapper;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.core.authorization.policy.MultipleAppPolicy;
import org.dom4j.Element;

import java.net.URL;
import java.security.Policy;
import java.util.Map;


public class AuthorizationModule extends AbstractModule {
    private AuthorizationScope authorizationScope;
    private Class<? extends AuthorizationManager> authorizationManagerClass;
    private URL authorizationConfigurationLocation;
    private URL applicationPath;

    public AuthorizationModule(AuthorizationScope authorizationScope,
                               Class<? extends AuthorizationManager> authorizationManagerClass,
                               URL authorizationConfigurationLocation,
                               URL applicationPath) {
        this.authorizationScope = authorizationScope;
        this.authorizationManagerClass = authorizationManagerClass;
        this.authorizationConfigurationLocation = authorizationConfigurationLocation;
        this.applicationPath = applicationPath;
    }

    protected void configure() {
        bind(URL.class).annotatedWith(ApplicationPath.class).toInstance(applicationPath);
        bind(AuthorizationScope.class).toInstance(authorizationScope);
        bind(AccessControllerWrapperImpl.class).toProvider(AccessControllerWrapperProvider.class);
        bind(Policy.class).toProvider(MultipleAppPolicyProvider.class);
        bind(MultipleAppPolicy.class).toProvider(MultipleAppPolicyProvider.class);
        bind(AuthorizationManager.class).to(authorizationManagerClass).in(Singleton.class);
        bind(URL.class).annotatedWith(AuthorizationConfigurationLocation.class).toInstance(authorizationConfigurationLocation);
        bind(new TypeLiteral<Element>() {
        }).annotatedWith(AuthorizationElement.class).toProvider(AuthorizationDOM4JElementProvider.class);
        bind(new TypeLiteral<Boolean>(){
        }).annotatedWith(NegativePermissions.class).toProvider(NegativePermissionsProvider.class);
        bind(new TypeLiteral<Boolean>(){
        }).annotatedWith(PermissionResolutionCaching.class).toProvider(PermissionResolutionCachingProvider.class);
        bind(new TypeLiteral<Map<String,String>>(){
                }).annotatedWith(AuthorizationManagerOptions.class).toProvider(AuthorizationManagerOptionsProvider.class);
        bind(new TypeLiteral<String>(){
                }).annotatedWith(AuthorizationXmlFileLocation.class).toProvider(AuthorizationXmlFileLocationProvider.class);
        bind(AccessControllerWrapper.class).to(AccessControllerWrapperImpl.class);
    }
}
