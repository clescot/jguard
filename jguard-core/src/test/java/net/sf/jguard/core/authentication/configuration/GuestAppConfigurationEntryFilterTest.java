package net.sf.jguard.core.authentication.configuration;

import com.sun.security.auth.module.KeyStoreLoginModule;
import net.sf.jguard.core.authentication.loginmodules.UserLoginModule;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.login.AppConfigurationEntry;
import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class GuestAppConfigurationEntryFilterTest {

    @Test
    public void testFilterWithUnknownClass() {
        GuestAppConfigurationEntryFilter filter = new GuestAppConfigurationEntryFilter();
        Map<String, ?> options = new HashMap<String, Object>();
        AppConfigurationEntry entry = new AppConfigurationEntry("toto", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        Assert.assertTrue(filter.filter(entry) == null);
    }

    @Test
    public void testFilterWithExistingClassButNotASubclassOfUserLoginModule() {
        GuestAppConfigurationEntryFilter filter = new GuestAppConfigurationEntryFilter();
        Map<String, ?> options = new HashMap<String, Object>();
        AppConfigurationEntry entry = new AppConfigurationEntry(KeyStoreLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        Assert.assertTrue(filter.filter(entry) == null);
    }

    @Test
    public void testFilterWithExistingClassAndASubclassOfUserLoginModule() {
        GuestAppConfigurationEntryFilter filter = new GuestAppConfigurationEntryFilter();
        Map<String, ?> options = new HashMap<String, Object>();
        AppConfigurationEntry entry = new AppConfigurationEntry(UserLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        AppConfigurationEntry returnedEntry = filter.filter(entry);
        Assert.assertTrue(returnedEntry != null);
        Assert.assertTrue(returnedEntry.getOptions().containsKey(UserLoginModule.SKIP_CREDENTIAL_CHECK));
        Assert.assertTrue(returnedEntry.getOptions().get(UserLoginModule.SKIP_CREDENTIAL_CHECK).equals(Boolean.TRUE.toString()));
    }
}
