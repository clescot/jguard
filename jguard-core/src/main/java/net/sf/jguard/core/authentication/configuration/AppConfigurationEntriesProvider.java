package net.sf.jguard.core.authentication.configuration;

import javax.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.PolicyEnforcementPointOptions;
import net.sf.jguard.core.authentication.LoginModuleControlFlag;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.authentication.manager.JGuardAuthenticationManagerMarkups;

import javax.security.auth.login.AppConfigurationEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AppConfigurationEntriesProvider implements Provider<List<AppConfigurationEntry>> {
    private String applicationName;
    private Map<String, Object> authenticationSettings;
    private AuthenticationManager authenticationManager;

    @Inject
    public AppConfigurationEntriesProvider(@ApplicationName String applicationName,
                                           @AuthenticationConfigurationSettings Map<String, Object> authenticationSettings,
                                           AuthenticationManager authenticationManager) {

        this.applicationName = applicationName;
        this.authenticationSettings = authenticationSettings;
        this.authenticationManager = authenticationManager;
    }

    public List<AppConfigurationEntry> get() {
        List<AppConfigurationEntry> appConfigurationEntryList = new ArrayList<AppConfigurationEntry>();

        List<Map<String, Object>> loginModules = (List<Map<String, Object>>) authenticationSettings.get(JGuardAuthenticationMarkups.LOGIN_MODULES.getLabel());
        if (loginModules == null) {
            throw new IllegalArgumentException(" no loginModules have been configured for the application=" + applicationName);
        }
        for (Map<String, Object> loginModuleMap : loginModules) {
            String loginModuleClassName = (String) loginModuleMap.get(JGuardAuthenticationMarkups.NAME.getLabel());
            LoginModuleControlFlag loginModuleFlag = LoginModuleControlFlag.valueOf((String) loginModuleMap.get(JGuardAuthenticationMarkups.FLAG.getLabel()));
            AppConfigurationEntry.LoginModuleControlFlag controlFlag;
            if (LoginModuleControlFlag.REQUIRED == loginModuleFlag) {
                controlFlag = AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
            } else if (LoginModuleControlFlag.OPTIONAL == loginModuleFlag) {
                controlFlag = AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL;
            } else if (LoginModuleControlFlag.REQUISITE == loginModuleFlag) {
                controlFlag = AppConfigurationEntry.LoginModuleControlFlag.REQUISITE;
            } else if (LoginModuleControlFlag.SUFFICIENT == loginModuleFlag) {
                controlFlag = AppConfigurationEntry.LoginModuleControlFlag.SUFFICIENT;
            } else {
                throw new IllegalArgumentException(" invalid loginModuleControlFlag =" + loginModuleFlag + " is neither OPTIONAL,REQUIRED,REQUISITE nor SUFFICIENT ");
            }
            Map<String, Object> loginModuleOptions = (Map<String, Object>) loginModuleMap.get(JGuardAuthenticationMarkups.LOGIN_MODULE_OPTIONS.getLabel());
            loginModuleOptions.put(PolicyEnforcementPointOptions.APPLICATION_NAME.getLabel(), applicationName);
            loginModuleOptions.put(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel(), authenticationManager);
            AppConfigurationEntry entry = new AppConfigurationEntry(loginModuleClassName, controlFlag, loginModuleOptions);
            appConfigurationEntryList.add(entry);
        }
        if (appConfigurationEntryList.size() == 0) {
            throw new IllegalArgumentException(" no loginModules have been configured for the application=" + applicationName);
        }
        return appConfigurationEntryList;
    }
}
