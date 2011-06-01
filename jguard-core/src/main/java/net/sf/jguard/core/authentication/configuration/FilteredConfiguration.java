package net.sf.jguard.core.authentication.configuration;

import javax.inject.Inject;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ListIterator;

/**
 * Provides a Configuration which exposes a subset of LoginModules and with some
 * specific options.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @see javax.security.auth.login.Configuration
 */
public class FilteredConfiguration extends Configuration {

    private Configuration configuration;
    private List<AppConfigurationEntryFilter> filters;

    @Inject
    public FilteredConfiguration(Configuration configuration, List<AppConfigurationEntryFilter> filters) {
        this.configuration = configuration;
        this.filters = filters;
    }


    /**
     * Retrieve the AppConfigurationEntries for the specified <i>name</i>
     * from this Configuration.
     * <p/>
     * <p/>
     *
     * @param name the name used to index the Configuration.
     * @return an array of AppConfigurationEntries for the specified <i>name</i>
     *         from this Configuration, or null if there are no entries
     *         for the specified <i>name</i>
     */
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        List<AppConfigurationEntry> entries = new ArrayList<AppConfigurationEntry>(Arrays.asList(configuration.getAppConfigurationEntry(name)));

        for (AppConfigurationEntryFilter filter : filters) {
            ListIterator<AppConfigurationEntry> entriesIterator = entries.listIterator();
            while (entriesIterator.hasNext()) {
                AppConfigurationEntry entry = entriesIterator.next();
                //entry is filtered
                AppConfigurationEntry filteredEntry = filter.filter(entry);
                if (filteredEntry  == null) {
                    entriesIterator.remove();
                }else{
                    entriesIterator.set(filteredEntry);
                }
            }
        }
        return entries.toArray(new AppConfigurationEntry[entries.size()]);
    }

    /**
     * Refresh and reload the Configuration.
     * <p/>
     * <p> This method causes this Configuration object to refresh/reload its
     * contents in an implementation-dependent manner.
     * For example, if this Configuration object stores its entries in a file,
     * calling <code>refresh</code> may cause the file to be re-read.
     * <p/>
     * <p/>
     *
     * @throws SecurityException if the caller does not have permission
     *                           to refresh its Configuration.
     */
    public void refresh() {
        configuration.refresh();
    }
}
