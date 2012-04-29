package net.sf.jguard.jee.authentication;

import com.google.inject.Module;
import com.mycila.testing.plugin.guice.Bind;
import com.mycila.testing.plugin.guice.ModuleProvider;
import net.sf.jguard.core.authentication.AuthenticationScope;
import net.sf.jguard.core.authentication.configuration.JGuardAuthenticationMarkups;
import net.sf.jguard.core.authentication.configuration.JGuardConfiguration;
import net.sf.jguard.core.authentication.loginmodules.UserNamePasswordLoginModule;
import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import net.sf.jguard.core.authorization.policy.AllAccessPolicy;
import net.sf.jguard.core.lifecycle.*;
import net.sf.jguard.core.test.JGuardTest;
import net.sf.jguard.ext.SecurityConstants;
import net.sf.jguard.ext.authentication.loginmodules.XmlLoginModule;
import net.sf.jguard.ext.authentication.manager.XmlAuthenticationManager;
import net.sf.jguard.ext.authorization.manager.XmlAuthorizationManager;
import org.junit.Assert;
import org.junit.Test;

import javax.inject.Inject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.net.URL;
import java.security.AccessControlException;
import java.security.Policy;
import java.security.PrivilegedActionException;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class JGuardConfigurationTest extends JGuardTest {


    @Inject
    public JGuardConfiguration jGuardConfiguration;

    @Bind
    Request request = new MockRequestAdapter(new MockRequest());
    @Bind
    Response response = new MockResponseAdapter(new MockResponse());

    @ModuleProvider
    public Iterable<Module> providesAuthenticationModule() {
        URL applicationPath = Thread.currentThread().getContextClassLoader().getResource(".");
        Collection modules = new ArrayList();
        modules.addAll(super.providesModules(
                AuthenticationScope.LOCAL,
                true,
                applicationPath,
                XmlAuthorizationManager.class));
        return modules;
    }


    @Test
    public void testGetApplicationEntry() {
        AppConfigurationEntry[] appConfigurationEntries = jGuardConfiguration.getAppConfigurationEntry(APPLICATION_NAME);
        List<AppConfigurationEntry> entries = Arrays.asList(appConfigurationEntries);
        AppConfigurationEntry firstEntry = entries.get(0);
        assertEquals("first AppConfigurationEntry should be configured with a class= " + XmlLoginModule.class.getName(), XmlLoginModule.class.getName(), firstEntry.getLoginModuleName());
        assertEquals("first AppConfigurationEntry should be configured with a flag Required ", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, firstEntry.getControlFlag());
        assertTrue(firstEntry.getOptions().containsKey(JGuardAuthenticationMarkups.DEBUG.getLabel()));
        assertTrue(firstEntry.getOptions().get(JGuardAuthenticationMarkups.DEBUG.getLabel()).equals(Boolean.FALSE.toString()));
        assertTrue(firstEntry.getOptions().get(SecurityConstants.AUTHORIZATION_DATABASE_IMPORT_XML_DATA).equals(Boolean.TRUE.toString()));
    }


    @Test(expected = IllegalArgumentException.class)
    public void testNullApplicationName() {
        String applicationName = null;
        Map<String, Object> authenticationSettings = new HashMap();
        List<AppConfigurationEntry> appConfigurationEntries = new ArrayList();
        new JGuardConfiguration(applicationName, authenticationSettings, appConfigurationEntries);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEmptyApplicationName() {
        String applicationName = "";
        Map<String, Object> authenticationSettings = new HashMap();
        List<AppConfigurationEntry> appConfigurationEntries = new ArrayList();
        new JGuardConfiguration(applicationName, authenticationSettings, appConfigurationEntries);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullAuthenticationSettings() {
        String applicationName = "dummy";
        Map<String, Object> authenticationSettings = null;
        List<AppConfigurationEntry> appConfigurationEntries = new ArrayList();
        new JGuardConfiguration(applicationName, authenticationSettings, appConfigurationEntries);
    }


    @Test(expected = IllegalArgumentException.class)
    public void testNullAppConigurationEntries() {
        String applicationName = "dummy";
        Map<String, Object> authenticationSettings = new HashMap();
        List<AppConfigurationEntry> appConfigurationEntries = null;
        new JGuardConfiguration(applicationName, authenticationSettings, appConfigurationEntries);
    }

    @Test(expected = AccessControlException.class)
    public void testRefresh_without_auth_permission() {
        jGuardConfiguration.refresh();
    }


    @Test
    public void testRefresh_with_auth_permission() throws PrivilegedActionException {

        //given
        Policy.setPolicy(new AllAccessPolicy());

        //when
        jGuardConfiguration.refresh();
        //then
        //no exception thrown
    }


    @Test
    public void test_addConfigurationEntriesForApplication() throws Exception {

        //given
        ArrayList<AppConfigurationEntry> entries = new ArrayList<AppConfigurationEntry>();
        entries.add(new AppConfigurationEntry("dummyLoginmoduleName", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap()));
        //when
        jGuardConfiguration.addConfigEntriesForApplication("dummyApplicationName", entries);

        //then

    }

    @Override
    protected AuthenticationManagerModule buildAuthenticationManagerModule() {
        return new AuthenticationManagerModule(APPLICATION_NAME, authenticationXmlFileLocation, XmlAuthenticationManager.class);
    }

    @Test
    public void testEquals() {
        List<AppConfigurationEntry> appConfigurationEntries = new ArrayList<AppConfigurationEntry>();
        Map<String, ?> entryOptions = new HashMap<String, Object>();
        appConfigurationEntries.add(new AppConfigurationEntry(UserNamePasswordLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, entryOptions));
        JGuardConfiguration jGuardConfiguration = new JGuardConfiguration("toto", new HashMap(), appConfigurationEntries);
        Configuration configuration = new Configuration() {

            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return new AppConfigurationEntry[0];
            }
        };

        Assert.assertNotSame(jGuardConfiguration, configuration);
    }


}
