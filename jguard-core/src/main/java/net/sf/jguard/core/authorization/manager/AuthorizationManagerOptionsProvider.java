package net.sf.jguard.core.authorization.manager;

import com.google.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.ApplicationPath;
import net.sf.jguard.core.util.XMLUtils;
import org.dom4j.Document;
import org.dom4j.Element;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static net.sf.jguard.core.authorization.manager.JGuardAuthorizationManagerMarkups.*;

public class AuthorizationManagerOptionsProvider implements Provider<Map<String, String>> {
    private static final String J_GUARD_AUTHORIZATION_2_00_XSD = "jGuardAuthorization_2.0.0.xsd";
    private URL authorizationConfigurationLocation;
    private URL appHomePath;

    @Inject
    public AuthorizationManagerOptionsProvider(@AuthorizationConfigurationLocation URL authorizationConfigurationLocation,
                                               @ApplicationPath URL appHomePath) {
        this.authorizationConfigurationLocation = authorizationConfigurationLocation;
        this.appHomePath = appHomePath;
    }


    public Map<String, String> get() {
        Map<String, String> authorizationMap = new HashMap<String, String>();
        URL xml;
        String xmlLocation;
        try {
            xmlLocation = XMLUtils.resolveLocation(authorizationConfigurationLocation.toString());
            xml = new URL(xmlLocation);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e);
        }
        Document doc = XMLUtils.read(xml, J_GUARD_AUTHORIZATION_2_00_XSD);

        Element authorization = doc.getRootElement();
        Element scope = authorization.element(SCOPE.getLabel());
        if (scope != null) {
            authorizationMap.put(SCOPE.getLabel(), scope.getTextTrim());
        }

        Element permissionResolutionCaching = authorization.element(AUTHORIZATION_PERMISSION_RESOLUTION_CACHING.getLabel());
        if (permissionResolutionCaching != null) {
            authorizationMap.put(AUTHORIZATION_PERMISSION_RESOLUTION_CACHING.getLabel(), permissionResolutionCaching.getTextTrim());
        }
        authorizationMap.put(AUTHORIZATION_MANAGER.getLabel(), authorization.element(AUTHORIZATION_MANAGER.getLabel()).getTextTrim());

        List authorizationList = authorization.element(AUTHORIZATION_MANAGER_OPTIONS.getLabel()).elements(OPTION.getLabel());
        for (Object anAuthorizationList : authorizationList) {
            Element option = (Element) anAuthorizationList;
            String name = option.element(NAME.getLabel()).getTextTrim();
            String value = option.element(VALUE.getLabel()).getTextTrim();
            if (AUTHORIZATION_XML_FILE_LOCATION.getLabel().equals(name) || AUTHORIZATION_DATABASE_FILE_LOCATION.getLabel().equals(name)) {
                value = appHomePath.toString() + value;
            }
            authorizationMap.put(name, value);
        }
        return authorizationMap;
    }

}
