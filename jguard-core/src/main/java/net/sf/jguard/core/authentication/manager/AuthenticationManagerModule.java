package net.sf.jguard.core.authentication.manager;

import com.google.inject.AbstractModule;
import javax.inject.Inject;
import com.google.inject.Singleton;
import net.sf.jguard.core.ApplicationName;

import java.net.URL;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class AuthenticationManagerModule extends AbstractModule {
    private String applicationName;
    private URL authenticationXmlFileLocation;
    private Class<? extends AuthenticationManager> authenticationManagerClass;


    @Inject
    public AuthenticationManagerModule(String applicationName,
                                       URL authenticationXmlFileLocation,
                                       Class<? extends AuthenticationManager> authenticationManagerClass) {
        if (applicationName == null || "".equals(applicationName)) {
            throw new IllegalArgumentException("applicationName must NOT be null");
        }
        this.applicationName = applicationName;
        if (authenticationXmlFileLocation == null) {
            throw new IllegalArgumentException("authenticationXmlFileLocation must NOT be null");
        }
        this.authenticationXmlFileLocation = authenticationXmlFileLocation;
        if (authenticationManagerClass == null) {
            throw new IllegalArgumentException("authenticationManagerClass must NOT be null");
        }
        this.authenticationManagerClass = authenticationManagerClass;
    }

    @Override
    protected void configure() {
        bind(String.class).annotatedWith(ApplicationName.class).toInstance(applicationName);
        bind(URL.class).annotatedWith(AuthenticationXmlStoreFileLocation.class).toInstance(authenticationXmlFileLocation);
        bind(AuthenticationManager.class).to(authenticationManagerClass).in(Singleton.class);
    }
}
