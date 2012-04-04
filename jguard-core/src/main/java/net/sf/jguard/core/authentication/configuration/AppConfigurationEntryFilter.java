package net.sf.jguard.core.authentication.configuration;

import javax.security.auth.login.AppConfigurationEntry;

/**
 * An AppConfigurationEntryFilter can be used to provide fine grain control over what is used ina Configuration instance for Authentication.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public interface AppConfigurationEntryFilter {


    /**
     * filter the AppConfigurationEntry by either returning null, or a AppConfigurationEntry
     * eventually modified.
     *
     * @param entry
     * @return null if entry is filtered, otherwise either the original, or
     *         a modified AppConfigurationEntry .
     */
    AppConfigurationEntry filter(AppConfigurationEntry entry);
}
