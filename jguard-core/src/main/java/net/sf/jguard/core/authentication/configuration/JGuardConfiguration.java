/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.

http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles GAY

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


jGuard project home page:
http://sourceforge.net/projects/jguard/

*/
package net.sf.jguard.core.authentication.configuration;


import com.google.inject.Inject;
import com.google.inject.Singleton;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.AuthenticationScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.AuthPermission;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.security.AccessController;
import java.security.Policy;
import java.security.PrivilegedAction;
import java.util.*;

import static net.sf.jguard.core.authentication.configuration.JGuardAuthenticationMarkups.INCLUDE_CONFIG_FROM_JAVA_PARAM;


/**
 * extends the <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/login/Configuration.html">
 * Configuration</a>
 * this class is used to define the authentication stack scheme per application.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
@Singleton
public final class JGuardConfiguration extends Configuration {


    private static Logger logger = LoggerFactory.getLogger(JGuardConfiguration.class.getName());

    private static boolean configurationInstalled = false;
    private final Collection<Configuration> internalConfigs;
    private final Map<String, List<AppConfigurationEntry>> appConfigurations;
    private static final String COM_SUN_SECURITY_AUTH_LOGIN_CONFIG_FILE = "com.sun.security.auth.login.ConfigFile";


    /**
     * constructor.
     *
     * @param applicationName
     * @param authenticationSettings
     * @param appConfigurationEntries
     */
    @Inject
    public JGuardConfiguration(@ApplicationName final String applicationName,
                               @AuthenticationConfigurationSettings final Map<String, Object> authenticationSettings,
                               final List<AppConfigurationEntry> appConfigurationEntries) {
        super();
        logger.debug("#####  JGuardConfiguration  #####");

        internalConfigs = new ArrayList<Configuration>();
        appConfigurations = new HashMap<String, List<AppConfigurationEntry>>();

        if (applicationName == null || "".equals(applicationName)) {
            throw new IllegalArgumentException(" String applicationName argument is empty or null");
        }

        if (authenticationSettings == null) {
            throw new IllegalArgumentException(" authenticationSettings argument null");
        }

        if (appConfigurationEntries == null || appConfigurationEntries.isEmpty()) {
            throw new IllegalArgumentException(" appConfigurationEntries argument is null or empty");
        }

        final JGuardConfiguration conf = this;
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                logger.debug("#####  Policy.getPolicy= #####" + Policy.getPolicy().getClass().getName());

                //add AppConfiguration related to the application
                addConfigEntriesForApplication(applicationName, appConfigurationEntries);

                //scope
                String scope = (String) authenticationSettings.get(JGuardAuthenticationMarkups.SCOPE.getLabel());
                AuthenticationScope authenticationScope;
                if (scope != null) {
                    authenticationScope = AuthenticationScope.valueOf((scope).toUpperCase());
                } else {
                    authenticationScope = AuthenticationScope.LOCAL;
                }

                //install configuration
                if (AuthenticationScope.JVM == authenticationScope) {
                    boolean includeConfigFromJavaParam = Boolean.valueOf((String) authenticationSettings.get(INCLUDE_CONFIG_FROM_JAVA_PARAM.getLabel()));
                    installConfiguration(conf, includeConfigFromJavaParam);
                }

                return null;
            }
        });

    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        JGuardConfiguration that = (JGuardConfiguration) o;

        if (!appConfigurations.equals(that.appConfigurations)) {
            return false;
        }
        return internalConfigs.equals(that.internalConfigs);

    }

    @Override
    public int hashCode() {
        int result = internalConfigs.hashCode();
        result = 31 * result + appConfigurations.hashCode();
        return result;
    }


    /**
     * reload the Configuration.
     *
     * @see javax.security.auth.login.Configuration#refresh()
     */
    public void refresh() {
        AccessController.checkPermission(new AuthPermission("refreshLoginConfiguration"));

        if (internalConfigs.size() > 0) {
            for (Object internalConfig : internalConfigs) {
                Configuration tempConfig = (Configuration) internalConfig;
                tempConfig.refresh();
            }
        }

    }

    /**
     * retrieve the AppConfigurationEntry array for the corresponding application's name.
     *
     * @param applicationName name of the application bound to AppConfigurationEntry seek
     * @return array of AppConfigurationEntry
     * @see javax.security.auth.login.Configuration#getAppConfigurationEntry(java.lang.String)
     */
    public AppConfigurationEntry[] getAppConfigurationEntry(
            String applicationName) {
        Collection<AppConfigurationEntry> appInternalEntries = new ArrayList<AppConfigurationEntry>();
        Iterator<Configuration> itConfigs = internalConfigs.iterator();
        while (itConfigs.hasNext()) {
            Configuration tempConfig = itConfigs.next();
            if (tempConfig == null) {
                itConfigs.remove();
                logger.warn("the default Configuration implementation has been removed from the JGuardConfiguration which imported it");
            } else if (tempConfig.getAppConfigurationEntry(applicationName) != null) {
                appInternalEntries.addAll(Arrays.asList(tempConfig.getAppConfigurationEntry(applicationName)));
            }
        }

        List<AppConfigurationEntry> jGuardAppConfigEntries = appConfigurations.get(applicationName);

        if (jGuardAppConfigEntries != null) {
            appInternalEntries.addAll(jGuardAppConfigEntries);
        }
        if (appInternalEntries.size() > 0) {
            return appInternalEntries.toArray(new AppConfigurationEntry[appInternalEntries.size()]);
        }

        return null;

    }


    /**
     * add AppconfigurationEntries for a specified application.
     *
     * @param applicationName name of the application owning appConfigurationEntries
     * @param entries         list of AppConfigurationEntry
     * @see javax.security.auth.login.Configuration#getAppConfigurationEntry(java.lang.String)
     */
    public void addConfigEntriesForApplication(String applicationName, List<AppConfigurationEntry> entries) {
        if (entries == null || entries.size() == 0) {
            throw new IllegalArgumentException("entries list is null or empty ");
        }

        List<AppConfigurationEntry> applicationEntries = appConfigurations.get(applicationName);
        if (applicationEntries == null) {
            //this application is not yet configured
            appConfigurations.put(applicationName, entries);
        }

        //we don't add other appConfigurationEntries if the application name already exists
        //because when webapp stops and start (but not app server), configuration for the application
        // will have twice loginmodules
    }

    /**
     * add the same AppconfigurationEntries like an already configured application.
     *
     * @param applicationName         name of the application to configure
     * @param applicationTemplateName name of the application
     *                                which will be the template to configure the first one.
     * @see javax.security.auth.login.Configuration#getAppConfigurationEntry(java.lang.String)
     */
    public void addConfigEntriesLikeApplication(String applicationName, String applicationTemplateName) {
        List<AppConfigurationEntry> applicationEntries = appConfigurations.get(applicationTemplateName);
        if (applicationEntries == null) {
            logger.error(" there is no applications registered with your applicationName and password ");
            return;
        }
        appConfigurations.put(applicationName, applicationEntries);
    }


    /**
     * include Configuration information, except from JGuardConfiguration to prevent an infinite loop.
     *
     * @param configuration
     */
    void includeConfiguration(Configuration configuration) {
        //we do not include a jGuardConfiguration to prevent infinite loop
        if (!configuration.getClass().getName().equals(JGuardConfiguration.class.getName())
                && !internalConfigs.contains(configuration)) {
            internalConfigs.add(configuration);
        }
    }


    /**
     * install JGuardConfiguration.
     *
     * @param jGuardConf                 Configuration to install
     * @param includeConfigFromJavaParam
     */
    void installConfiguration(JGuardConfiguration jGuardConf, boolean includeConfigFromJavaParam) {
        if (!configurationInstalled) {
            includeConfigFromJavaParam = false;
        }

        if (includeConfigFromJavaParam) {
            //TODO build a Configuration object to include from the configuration file
            try {
                Class defaultConfigClass = Class.forName(COM_SUN_SECURITY_AUTH_LOGIN_CONFIG_FILE);
                Configuration defaultConfiguration = (Configuration) defaultConfigClass.newInstance();
                jGuardConf.includeConfiguration(defaultConfiguration);
            } catch (ClassNotFoundException e) {
                logger.error(COM_SUN_SECURITY_AUTH_LOGIN_CONFIG_FILE + " class cannot be found " + e.getMessage(), e);
            } catch (InstantiationException e) {
                logger.error(COM_SUN_SECURITY_AUTH_LOGIN_CONFIG_FILE + " class cannot be instantiated " + e.getMessage(), e);
            } catch (IllegalAccessException e) {
                logger.error(COM_SUN_SECURITY_AUTH_LOGIN_CONFIG_FILE + " class cannot be accessed " + e.getMessage(), e);
            }

        }

    }

}
