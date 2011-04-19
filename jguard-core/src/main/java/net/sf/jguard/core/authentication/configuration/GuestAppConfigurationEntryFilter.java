package net.sf.jguard.core.authentication.configuration;

import net.sf.jguard.core.authentication.loginmodules.UserLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.AppConfigurationEntry;
import java.util.HashMap;
import java.util.Map;

import static net.sf.jguard.core.authentication.loginmodules.UserLoginModule.SKIP_CREDENTIAL_CHECK;

/**
 * Filter used to remove loginModules not involved in population of a Subject,
 * and to put some special options to disable authentication checking, to authenticate as Guest.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class GuestAppConfigurationEntryFilter implements AppConfigurationEntryFilter {


    private Logger logger = LoggerFactory.getLogger(GuestAppConfigurationEntryFilter.class);

    /**
     * return null if the AppconfigurationEntry does not inherit from UserLoginModule,
     * otherwise, add a SKIP_CREDENTIAL_CHECK option to true to the map options.
     *
     * @param entry
     * @return null if entry is filtered, otherwise either the original, or
     *         a modified AppConfigurationEntry .
     */
    public AppConfigurationEntry filter(AppConfigurationEntry entry) {
        Class clazz;
        try {
            clazz = Class.forName(entry.getLoginModuleName());
            boolean assignable = UserLoginModule.class.isAssignableFrom(clazz);
            if (assignable) {
                Map<String, Object> options = new HashMap<String, Object>(entry.getOptions());
                options.put(SKIP_CREDENTIAL_CHECK, "true");
                return new AppConfigurationEntry(entry.getLoginModuleName(), entry.getControlFlag(), options);
            }
            return null;
        } catch (ClassNotFoundException e) {
            logger.error("class " + entry.getLoginModuleName() + "configured in Configuration cannot be loaded", e);
            return null;
        }

    }
}
