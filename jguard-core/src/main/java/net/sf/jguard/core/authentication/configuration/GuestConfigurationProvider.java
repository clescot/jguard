package net.sf.jguard.core.authentication.configuration;

import javax.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.authentication.Guest;

import javax.security.auth.login.Configuration;
import java.util.List;

/**
 * return a FilteredConfiguration composed of the initial Configuration and the AppconfigurationEntryFilter list.
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class GuestConfigurationProvider implements Provider<Configuration> {
    private Configuration configuration;
    private List<AppConfigurationEntryFilter> filters;

    @Inject
    public GuestConfigurationProvider(Configuration configuration, @Guest List<AppConfigurationEntryFilter> filters) {
        this.configuration = configuration;
        this.filters = filters;
    }

    public Configuration get() {
        return new FilteredConfiguration(configuration, filters);
    }
}
