package net.sf.jguard.core.authentication.configuration;

import com.google.inject.Inject;
import com.google.inject.Provider;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class GuestAppConfigurationFiltersListProvider implements Provider<List<AppConfigurationEntryFilter>> {
    private AppConfigurationEntryFilter appConfigurationEntryFilter;

    @Inject
    public GuestAppConfigurationFiltersListProvider(AppConfigurationEntryFilter appConfigurationEntryFilter){
        this.appConfigurationEntryFilter = appConfigurationEntryFilter;
    }

    public List<AppConfigurationEntryFilter> get() {
         List<AppConfigurationEntryFilter> filters = new ArrayList<AppConfigurationEntryFilter>();
        filters.add(appConfigurationEntryFilter);
        return filters;
    }
}
