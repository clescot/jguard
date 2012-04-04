package net.sf.jguard.core.authentication.configuration;

import com.google.inject.Provider;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.AuthenticationScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.List;
import java.util.Map;

/**
 * Provides a {@link net.sf.jguard.core.authentication.configuration.JGuardConfiguration} instance.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class JGuardConfigurationProvider implements Provider<JGuardConfiguration> {

    private static final Logger logger = LoggerFactory.getLogger(JGuardConfigurationProvider.class.getName());
    private AuthenticationScope authenticationScope;
    private String applicationName;
    private Map<String, Object> authenticationSettings;
    private List<AppConfigurationEntry> appConfigurationEntries;
    private JGuardConfiguration jGuardConf;


    @Inject
    public JGuardConfigurationProvider(AuthenticationScope authenticationScope,
                                       @ApplicationName String applicationName,
                                       @AuthenticationConfigurationSettings Map<String, Object> authenticationSettings,
                                       List<AppConfigurationEntry> appConfigurationEntries) {
        this.authenticationScope = authenticationScope;
        this.applicationName = applicationName;
        this.authenticationSettings = authenticationSettings;
        this.appConfigurationEntries = appConfigurationEntries;
    }

    public JGuardConfiguration get() {

        if(jGuardConf!=null){
            return jGuardConf;
        }
        logger.debug(" ### initializing jGuard Configuration ### ");
        if (AuthenticationScope.JVM == authenticationScope) {
            jGuardConf = (JGuardConfiguration) Configuration.getConfiguration();
        } else {
            jGuardConf = new JGuardConfiguration(applicationName, authenticationSettings,appConfigurationEntries);
        }

        logger.debug(" ### jGuard Configuration initialized ### ");

        return jGuardConf;
    }
}
