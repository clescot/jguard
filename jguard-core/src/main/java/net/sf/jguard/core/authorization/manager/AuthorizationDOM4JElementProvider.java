package net.sf.jguard.core.authorization.manager;

import com.google.inject.Provider;
import net.sf.jguard.core.ApplicationPath;
import net.sf.jguard.core.util.XMLUtils;
import org.dom4j.Document;
import org.dom4j.Element;

import javax.inject.Inject;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class AuthorizationDOM4JElementProvider implements Provider<Element> {

    private final URL authorizationConfigurationLocation;
    private static final String J_GUARD_AUTHORIZATION_2_00_XSD = "jGuardAuthorization_2.0.0.xsd";

    @Inject
    public AuthorizationDOM4JElementProvider(@AuthorizationConfigurationLocation URL authorizationConfigurationLocation){

        this.authorizationConfigurationLocation = authorizationConfigurationLocation;
    }
    public Element get() {
        URL xml;
        String xmlLocation;
        try {
            xmlLocation = XMLUtils.resolveLocation(authorizationConfigurationLocation.toString());
            xml = new URL(xmlLocation);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e);
        }
        Document doc = XMLUtils.read(xml, J_GUARD_AUTHORIZATION_2_00_XSD);

        return doc.getRootElement();
    }
}
