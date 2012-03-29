package net.sf.jguard.core.jmx;

import com.google.inject.Provider;
import net.sf.jguard.core.authorization.AuthorizationScope;
import net.sf.jguard.core.authorization.policy.AccessControllerWrapperImpl;
import net.sf.jguard.core.authorization.policy.LocalAccessController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.management.MBeanServer;
import javax.management.remote.*;
import javax.management.remote.rmi.RMIConnectorServer;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

class JMXConnectorServerProvider implements Provider<JMXConnectorServer> {
    private boolean enableJMX;
    private JMXAuthenticator jmxAuthenticator;
    private JMXServiceURL jmxServiceURL;
    private MBeanServer mBeanServer;
    private AuthorizationScope authorizationScope;
    private LocalAccessController localAccessController;
    private AccessControllerWrapperImpl accessControlWrapper;
    private static final String JAVA_NAMING_FACTORY_INITIAL = "java.naming.factory.initial";
    private static final String COM_SUN_JNDI_RMI_REGISTRY_REGISTRY_CONTEXT_FACTORY = "com.sun.jndi.rmi.registry.RegistryContextFactory";
    private static final Logger logger = LoggerFactory.getLogger(JMXConnectorServerProvider.class.getName());


    @Inject
    public JMXConnectorServerProvider(JMXAuthenticator jmxAuthenticator,
                                      JMXServiceURL jmxServiceURL,
                                      MBeanServer mBeanServer,
                                      AuthorizationScope authorizationScope,
                                      LocalAccessController localAccessController) {
        this.jmxAuthenticator = jmxAuthenticator;
        this.jmxServiceURL = jmxServiceURL;
        this.mBeanServer = mBeanServer;
        this.authorizationScope = authorizationScope;
        this.localAccessController = localAccessController;
    }

    public JMXConnectorServer get() {
        Map<String, Object> options = new HashMap<String, Object>();
        options.put(JMXConnectorServer.AUTHENTICATOR, jmxAuthenticator);
        options.put(JAVA_NAMING_FACTORY_INITIAL, COM_SUN_JNDI_RMI_REGISTRY_REGISTRY_CONTEXT_FACTORY);
        options.put(RMIConnectorServer.JNDI_REBIND_ATTRIBUTE, Boolean.TRUE.toString());
        JMXConnectorServer connectorServer = null;
        try {
            connectorServer = JMXConnectorServerFactory.newJMXConnectorServer(jmxServiceURL, options, mBeanServer);

            //we are in 'local' mode
            if (AuthorizationScope.LOCAL.equals(authorizationScope)) {
                MBeanServerForwarder msf = new MBeanServerGuard(localAccessController);
                connectorServer.setMBeanServerForwarder(msf);
            }
            connectorServer.start();
        } catch (IOException e) {
            logger.error("IOException : " + e.getMessage(), e);
        }
        return connectorServer;
    }
}
