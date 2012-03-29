package net.sf.jguard.core.jmx;

import com.google.inject.Provider;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.AuthenticationScope;

import javax.inject.Inject;
import javax.management.remote.JMXAuthenticator;
import javax.security.auth.login.Configuration;

class JMXAuthenticatorProvider implements Provider<JMXAuthenticator> {
    private String applicationName;
    private AuthenticationScope authenticationScope;
    private Configuration configuration;

    @Inject
    public JMXAuthenticatorProvider(@ApplicationName String applicationName,
                                    AuthenticationScope authenticationScope,
                                    Configuration configuration) {
        this.applicationName = applicationName;
        this.authenticationScope = authenticationScope;
        this.configuration = configuration;
    }

    public JGuardJMXAuthenticator get() {
        JGuardJMXAuthenticator jmxAuthenticator;
        if (AuthenticationScope.LOCAL.equals(authenticationScope)) {
            jmxAuthenticator = new JGuardJMXAuthenticator(applicationName, Thread.currentThread().getContextClassLoader(), configuration);
        } else {
            jmxAuthenticator = new JGuardJMXAuthenticator(applicationName, Thread.currentThread().getContextClassLoader());
        }

        return jmxAuthenticator;
    }
}
