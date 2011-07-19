package net.sf.jguard.core.authorization.manager;

import javax.inject.Inject;
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
    private URL appHomePath;
    private final Element authorizationElement;

    @Inject
    public AuthorizationManagerOptionsProvider(@ApplicationPath URL appHomePath,@AuthorizationElement Element authorizationElement) {
        this.appHomePath = appHomePath;
        this.authorizationElement = authorizationElement;
    }


    public Map<String, String> get() {
        Map<String, String> authorizationMap = new HashMap<String, String>();

        List authorizationList = authorizationElement.element(AUTHORIZATION_MANAGER_OPTIONS.getLabel()).elements(OPTION.getLabel());
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
