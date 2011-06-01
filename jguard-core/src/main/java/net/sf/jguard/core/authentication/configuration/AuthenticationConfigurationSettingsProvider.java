package net.sf.jguard.core.authentication.configuration;

import javax.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.authentication.manager.JGuardAuthenticationManagerMarkups;
import net.sf.jguard.core.util.XMLUtils;
import org.dom4j.Document;
import org.dom4j.Element;

import java.net.URL;
import java.util.*;

import static net.sf.jguard.core.authentication.configuration.JGuardAuthenticationMarkups.*;

public class AuthenticationConfigurationSettingsProvider implements Provider<Map<String, Object>> {
    private URL configurationLocation;
    private static final String J_GUARD_AUTHENTICATION_200_XSD = "jGuardAuthentication_2.0.0.xsd";

    @Inject
    public AuthenticationConfigurationSettingsProvider(@AuthenticationConfigurationLocation URL configurationXmlFileLocation) {
        this.configurationLocation = configurationXmlFileLocation;
    }


    public
    @AuthenticationConfigurationSettings
    Map<String, Object> get() {
        Document doc = XMLUtils.read(configurationLocation, J_GUARD_AUTHENTICATION_200_XSD);

        //authentication part
        Element authentication = doc.getRootElement();
        Map<String, Object> authenticationOptions = new HashMap<String, Object>();
        authenticationOptions.put(SCOPE.getLabel(), authentication.element(SCOPE.getLabel()).getTextTrim());
        authenticationOptions.put(DEBUG.getLabel(), authentication.element(DEBUG.getLabel()).getTextTrim());
        authenticationOptions.put(INCLUDE_OLD_CONFIG.getLabel(), authentication.element(INCLUDE_OLD_CONFIG.getLabel()).getTextTrim());
        authenticationOptions.put(INCLUDE_CONFIG_FROM_JAVA_PARAM.getLabel(), authentication.element(INCLUDE_CONFIG_FROM_JAVA_PARAM.getLabel()).getTextTrim());
        authenticationOptions.put(INCLUDE_POLICY_FROM_JAVA_PARAM.getLabel(), authentication.element(INCLUDE_POLICY_FROM_JAVA_PARAM.getLabel()).getTextTrim());
        if (authentication.element(DIGEST_ALGORITHM.getLabel()) != null) {
            authenticationOptions.put(DIGEST_ALGORITHM.getLabel(), authentication.element(DIGEST_ALGORITHM.getLabel()).getTextTrim());
        }
        if (authentication.element(SALT.getLabel()) != null) {
            authenticationOptions.put(SALT.getLabel(), authentication.element(SALT.getLabel()).getTextTrim());
        }
        //loginModules configuration
        List loginModuleElementsList = authentication.element(LOGIN_MODULES.getLabel()).elements(LOGIN_MODULE.getLabel());
        List loginModules = new ArrayList();
        for (Object aLoginModuleElementsList : loginModuleElementsList) {
            Element loginModule = (Element) aLoginModuleElementsList;

            Map<String, Object> loginModuleMap = new HashMap<String, Object>();
            loginModuleMap.put(NAME.getLabel(), loginModule.element(NAME.getLabel()).getTextTrim());
            loginModuleMap.put(FLAG.getLabel(), loginModule.element(FLAG.getLabel()).getTextTrim());
            Element loginModuleOpts = loginModule.element(LOGIN_MODULE_OPTIONS.getLabel());
            if (loginModuleOpts != null) {
                List loginModuleOptsList = loginModuleOpts.elements(OPTION.getLabel());
                Iterator itLoginModuleOpts = loginModuleOptsList.iterator();
                Map<String, String> loginModulesOptions = new HashMap<String, String>();
                while (itLoginModuleOpts.hasNext()) {
                    Element option = (Element) itLoginModuleOpts.next();
                    String name = option.element(NAME.getLabel()).getTextTrim();
                    String value = option.element(VALUE.getLabel()).getTextTrim();
                    loginModulesOptions.put(name, value);
                }
                loginModuleMap.put(LOGIN_MODULE_OPTIONS.getLabel(), loginModulesOptions);
            } else {
                //there are no options for the loginmodule
                loginModuleMap.put(LOGIN_MODULE_OPTIONS.getLabel(), new HashMap<String, String>());
            }
            loginModules.add(loginModuleMap);
        }

        authenticationOptions.put(LOGIN_MODULES.getLabel(), loginModules);

        //authenticationManager configuration
        authenticationOptions.put(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel(), authentication.element(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel()).getTextTrim());

        Map<String, String> authenticationManagerOptions = new HashMap<String, String>();
        Element authentManagerOptsElement = authentication.element(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER_OPTIONS.getLabel());
        List<Element> authentManagerOptsList = authentManagerOptsElement.elements(OPTION.getLabel());
        for (Element option : authentManagerOptsList) {
            String name = option.element(NAME.getLabel()).getTextTrim();
            String value = option.element(VALUE.getLabel()).getTextTrim();
            authenticationManagerOptions.put(name, value);
        }

        authenticationOptions.put(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER_OPTIONS.getLabel(), authenticationManagerOptions);

        return authenticationOptions;
    }
}
