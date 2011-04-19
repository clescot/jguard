package net.sf.jguard.core.authorization;

import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import net.sf.jguard.core.authorization.manager.AuthorizationManager;
import net.sf.jguard.core.authorization.policy.MultipleAppPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.Permissions;
import java.security.Policy;
import java.util.Enumeration;
import java.util.Properties;

/**
 * Provides a {@link java.security.Policy} implementation.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
@Singleton
class MultipleAppPolicyProvider implements Provider<MultipleAppPolicy> {
    private static final Logger logger = LoggerFactory.getLogger(MultipleAppPolicyProvider.class.getName());
    private AuthorizationScope authorizationScope;
    private AuthorizationManager authorizationManager;
    private Permissions permissions;
    private static final String COM_SUN_SECURITY_AUTH_POLICY_FILE = "com.sun.security.auth.PolicyFile";
    private MultipleAppPolicy policy;

    @Inject
    public MultipleAppPolicyProvider(AuthorizationScope authorizationScope, AuthorizationManager authorizationManager, Permissions permissions) {
        this.authorizationScope = authorizationScope;
        this.authorizationManager = authorizationManager;
        this.permissions = permissions;
    }

    public MultipleAppPolicy get() {
        if (policy != null) {
            return policy;
        }
        if (AuthorizationScope.JVM == authorizationScope) {
            installPolicyOnJVM();
            //Register the new authorization manager with jguard policy provider
            policy = (MultipleAppPolicy) Policy.getPolicy();
        } else {
            policy = new MultipleAppPolicy(permissions);
        }
        policy.registerPermissionProvider(Thread.currentThread().getContextClassLoader(), authorizationManager);
        return policy;
    }

    /**
     * install the jGuardPolicy if the default policy of the platform is not
     * a jGuardPolicy instance.
     */
    private void installPolicyOnJVM() {

        Policy runtimePolicy = Policy.getPolicy();

        //the jGuard Policy is not set as the policy provider
        if (!(runtimePolicy.getClass().getName().equals(MultipleAppPolicy.class.getName()))) {

            logger.info("init() -  JGuardPolicy is not set as the policy provider . the actual policy provider is '" + runtimePolicy.getClass().getName() + "' which is different of '" + MultipleAppPolicy.class.getName() + "' ");
            logger.info("init() -  if you want the jGuard policy 'governs' all java applications (one choice among others described in the jGuard documentation),");
            logger.info("init() -  please correct the 'policy.provider' property (policy.provider=net.sf.jguard.core.JGuardPolicy) in  your 'java.security' file,");
            logger.info("init() -  located in this directory: " + System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator);

            try {
                //we set the old policy to the Sun's Policy implementation
                try {
                    Class clazz = Class.forName(COM_SUN_SECURITY_AUTH_POLICY_FILE);
                    //we have tested that the com.sun.security.auth.PolicyFile is reachable
                    javax.security.auth.Policy.setPolicy((javax.security.auth.Policy) clazz.newInstance());
                } catch (ClassNotFoundException e) {
                    logger.warn("com.sun.security.auth.PolicyFile is not reachable.\n we cannot set the old javax.security.auth.Policy implementation to it\n " + e.getMessage());
                }

                //give to the new JGuardPolicy the old Policy instance
                Policy.setPolicy(new MultipleAppPolicy(Policy.getPolicy(), permissions));

            } catch (InstantiationException e) {
                logger.error("init() -  Policy Implementation cannot be instantiated : InstantiationException" + e.getMessage(), e);
            } catch (IllegalAccessException e) {
                logger.error("init() -  Policy Implementation cannot be accessed : IllegalAccessException" + e.getMessage(), e);
            } catch (SecurityException e) {
                logger.error("init() -  Policy Implementation cannot be defined : SecurityException . you haven't got the right to set the java policy" + e.getMessage(), e);
            }
        }

        try {

            logger.debug("System properties : \n");
            Properties props = System.getProperties();
            Enumeration enumeration = props.keys();
            while (enumeration.hasMoreElements()) {
                String key = (String) enumeration.nextElement();
                String value = (String) props.get(key);
                logger.debug(key + "=" + value);
            }

        } catch (SecurityException sex) {
            logger.warn("you have not the permission to grab system properties ");
        }

    }

}
