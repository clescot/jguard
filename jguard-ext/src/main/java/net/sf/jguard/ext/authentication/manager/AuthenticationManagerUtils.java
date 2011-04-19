package net.sf.jguard.ext.authentication.manager;

import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.util.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

public class AuthenticationManagerUtils {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationManagerUtils.class.getName());

    public static String exportAsXMLString(AuthenticationManager authenticationManager, Map authenticationManagerOptions) {
        XmlAuthenticationManager xmlAuthenticationManager = exportAsXmlAuthenticationManager(authenticationManager, authenticationManagerOptions);
        return xmlAuthenticationManager.exportAsXMLString();
    }

    /**
     * return a <strong>new</strong> XmlAuthenticationManager although if the parameter is already an XmlAuthenticationManager.
     *
     * @param authenticationManager
     * @return
     */
    public static XmlAuthenticationManager exportAsXmlAuthenticationManager(AuthenticationManager authenticationManager, Map authenticationManagerOptions) {
        XmlAuthenticationManager xmlAuthenticationManager;

        String fileLocation = (String) authenticationManagerOptions.get(AbstractAuthenticationManager.AUTHENTICATION_XML_FILE_LOCATION);

        if (fileLocation == null) {
            logger.error(" parameter '" + AbstractAuthenticationManager.AUTHENTICATION_XML_FILE_LOCATION + "' which is null must be specified in the authentication configuration ");
        }
        if (logger.isDebugEnabled()) {
            logger.debug("initAuthenticationDAO() - fileLocation=" + fileLocation);
        }
        URL xmlAuthenticationManagerLocation;
        try {
            xmlAuthenticationManagerLocation = new URL(XMLUtils.resolveLocation(fileLocation));
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        xmlAuthenticationManager = new XmlAuthenticationManager(authenticationManager.getApplicationName(), xmlAuthenticationManagerLocation);
        xmlAuthenticationManager.importAuthenticationManager(authenticationManager);

        return xmlAuthenticationManager;
    }

    public static void writeAsHTML(AuthenticationManager authenticationManager, Map authenticationManagerOptions, OutputStream outputStream) throws IOException {
        XmlAuthenticationManager xmlAuthenticationManager = exportAsXmlAuthenticationManager(authenticationManager, authenticationManagerOptions);
        xmlAuthenticationManager.writeAsHTML(outputStream);
    }

    public static void writeAsXML(AuthenticationManager authenticationManager, Map authenticationManagerOptions, OutputStream outputStream, String encodingScheme) throws IOException {
        XmlAuthenticationManager xmlAuthenticationManager = exportAsXmlAuthenticationManager(authenticationManager, authenticationManagerOptions);
        xmlAuthenticationManager.writeAsXML(outputStream, encodingScheme);
    }

    public static void exportAsXMLFile(AuthenticationManager authenticationManager, Map authenticationManagerOptions, String fileName) throws IOException {
        XmlAuthenticationManager xmlAuthenticationManager = exportAsXmlAuthenticationManager(authenticationManager, authenticationManagerOptions);
        xmlAuthenticationManager.exportAsXMLFile(fileName);
    }


}
