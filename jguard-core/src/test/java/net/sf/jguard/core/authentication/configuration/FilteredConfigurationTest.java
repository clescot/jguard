package net.sf.jguard.core.authentication.configuration;

import net.sf.jguard.core.authentication.loginmodules.UserNamePasswordLoginModule;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.*;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class FilteredConfigurationTest {

    private final String applicationName = "dummyName";

    @Test
    public void testGetAppConfigurationEntryIsConformToFilters() {
        Map<String, ?> entryOptions = new HashMap<String, Object>();
        AppConfigurationEntry entry = new AppConfigurationEntry(UserNamePasswordLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, entryOptions);

        Configuration configuration = getUnderlyingConfiguration(entry);
        List<AppConfigurationEntryFilter> filters = buildFiltersWithOneNullFilter();


        //build wrapper configuration
        FilteredConfiguration filteredConfiguration = new FilteredConfiguration(configuration, filters);

        //test
        List<AppConfigurationEntry> filteredAppConfigurationEntries = Arrays.asList(filteredConfiguration.getAppConfigurationEntry(applicationName));
        boolean contains = filteredAppConfigurationEntries.contains(entry);
        Assert.assertFalse(contains);


    }

    @Test
    public void testGetAppCOnfigurationEntryWithaNoEffectFilter() {
        Map<String, ?> entryOptions = new HashMap<String, Object>();
        AppConfigurationEntry entry = new AppConfigurationEntry(UserNamePasswordLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, entryOptions);

        Configuration configuration = getUnderlyingConfiguration(entry);
        List<AppConfigurationEntryFilter> filters = buildFiltersWithOneNoEffectFilter();


        //build wrapper configuration
        FilteredConfiguration filteredConfiguration = new FilteredConfiguration(configuration, filters);

        //test
        List<AppConfigurationEntry> filteredAppConfigurationEntries = Arrays.asList(filteredConfiguration.getAppConfigurationEntry(applicationName));
        boolean contains = filteredAppConfigurationEntries.contains(entry);
        Assert.assertTrue(contains);

    }

    private Configuration getUnderlyingConfiguration(AppConfigurationEntry entry) {
        Map<String, Object> authenticationSettings = new HashMap<String, Object>();

        //initial appConfigurationEntries
        List<AppConfigurationEntry> appConfigurationEntries = new ArrayList<AppConfigurationEntry>();


        appConfigurationEntries.add(entry);

        //build underlying configuration
        Configuration configuration = new JGuardConfiguration(applicationName, authenticationSettings, appConfigurationEntries);
        return configuration;
    }

    private List<AppConfigurationEntryFilter> buildFiltersWithOneNullFilter() {
        //configure filters
        List<AppConfigurationEntryFilter> filters = new ArrayList<AppConfigurationEntryFilter>();
        AppConfigurationEntryFilter nullAppConfigurationEntryFilter = new AppConfigurationEntryFilter() {

            public AppConfigurationEntry filter(AppConfigurationEntry entry) {
                return null;
            }
        };
        filters.add(nullAppConfigurationEntryFilter);
        return filters;
    }


    private List<AppConfigurationEntryFilter> buildFiltersWithOneNoEffectFilter() {
        //configure filters
        List<AppConfigurationEntryFilter> filters = new ArrayList<AppConfigurationEntryFilter>();
        AppConfigurationEntryFilter nullAppConfigurationEntryFilter = new AppConfigurationEntryFilter() {

            public AppConfigurationEntry filter(AppConfigurationEntry entry) {
                return entry;
            }
        };
        filters.add(nullAppConfigurationEntryFilter);
        return filters;
    }


    /**
     * we check that the wrapping  instance, calls the underlying configuration with the 'refresh' method,
     * when we call its 'refresh' method.
     */
    @Test
    public void testRefresh() {
        Configuration configuration = mock(Configuration.class);
        FilteredConfiguration filteredConfiguration = new FilteredConfiguration(configuration, buildFiltersWithOneNullFilter());
        filteredConfiguration.refresh();
        verify(configuration).refresh();
    }
}
