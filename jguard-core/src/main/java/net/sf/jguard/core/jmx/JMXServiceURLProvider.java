package net.sf.jguard.core.jmx;

import com.google.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.ApplicationName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.remote.JMXServiceURL;
import java.net.MalformedURLException;

class JMXServiceURLProvider implements Provider<JMXServiceURL> {
    private String rmiRegistryHost;
    private String rmiRegistryPort;
    private String applicationName;
    private static final Logger logger = LoggerFactory.getLogger(JMXServiceURLProvider.class.getName());
    private static final String SERVICE_JMX_RMI_LOCALHOST_JNDI_RMI = "service:jmx:rmi://localhost/jndi/rmi://";


    @Inject
    public JMXServiceURLProvider(@RmiRegistryHost String rmiRegistryHost,
                                 @RmiRegistryPort String rmiRegistryPort,
                                 @ApplicationName String applicationName) {
        this.rmiRegistryHost = rmiRegistryHost;
        this.rmiRegistryPort = rmiRegistryPort;
        this.applicationName = applicationName;
    }

    public JMXServiceURL get() {

        String serviceURL = SERVICE_JMX_RMI_LOCALHOST_JNDI_RMI + rmiRegistryHost + ":" + rmiRegistryPort + "/" + applicationName;
        JMXServiceURL url = null;
        try {
            url = new JMXServiceURL(serviceURL);
            logger.info("JMX Server URL : " + url.toString());
        } catch (MalformedURLException e) {
            logger.error("MalformedURLException : " + e);
        }

        return null;
    }
}
