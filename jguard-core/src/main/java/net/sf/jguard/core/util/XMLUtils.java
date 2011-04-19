/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name:  $
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
package net.sf.jguard.core.util;

import net.sf.jguard.core.principals.RolePrincipal;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

/**
 * Utility class to handle XML documents with DOM4J.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class XMLUtils {

    private static final String UTF_8 = "UTF-8";

    private static final String JAXP_SCHEMA_LANGUAGE = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
    private static final String JAXP_XML_SCHEMA_LANGUAGE = "http://www.w3.org/2001/XMLSchema";
    private static final String JAXP_SCHEMA_SOURCE = "http://java.sun.com/xml/jaxp/properties/schemaSource";
    private static final String XML_VALIDATION = "http://xml.org/sax/features/validation";
    private static final String APACHE_VALIDATION = "http://apache.org/xml/features/validation/schema";

    private static Logger logger = LoggerFactory.getLogger(XMLUtils.class.getName());
    private static final String PRINCIPALS = "principals";
    private static final String PRINCIPAL_REF = "principalRef";
    private static final String FILE_URL_PREFIX = "file://////";
    private static final String PRINCIPAL_REF_NAME_REGEXP = "//principalRef[@name='";
    private static final String SLASH = "/";

    /**
     * this constructor is protected to prevent any instantiation
     * which is <a href="http://checkstyle.sourceforge.net/config_design.html#HideUtilityClassConstructor">a non-sense in an utility class</a>.
     */
    private XMLUtils() {
        throw new UnsupportedOperationException(); // prevents calls from subclass
    }

    public static Document read(URL xml, String schema) {
        URL schemaURL = calculateSchemaLocation(xml, schema);
        if (logger.isDebugEnabled()) {
            logger.debug("xml url=" + xml.toExternalForm() + " schema url=" + schemaURL.toExternalForm());
        }
        InputSource inputSource = new InputSource(schemaURL.toExternalForm());
        return read(xml, inputSource);

    }


    /**
     * read the xml data storage file for users and associated principals.
     *
     * @param xml    file location to read
     * @param schema
     * @return xml content
     */
    public static Document read(URL xml, InputSource schema) {

        SAXReader reader = new SAXReader(true);
        Document document;

        try {
            //activate schema validation
            reader.setFeature(XML_VALIDATION, true);
            reader.setFeature(APACHE_VALIDATION, true);
            reader.setProperty(JAXP_SCHEMA_LANGUAGE, JAXP_XML_SCHEMA_LANGUAGE);
            reader.setProperty(JAXP_SCHEMA_SOURCE, schema);

        } catch (SAXException ex) {
            logger.error("read(String) : " + ex.getMessage(), ex);
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }

        try {
            document = reader.read(xml);
        } catch (DocumentException e1) {
            logger.error("read(String) : " + e1, e1);
            throw new IllegalArgumentException(e1.getMessage(), e1);
        }

        if (document == null) {
            logger.warn("we create a default document");
            document = DocumentHelper.createDocument();
        }
        return document;
    }


    public static String resolveLocation(String location) {
        if (location == null) {
            throw new IllegalArgumentException(" location is null ");
        }

        //if it does not contains a ':' which is used with a protocol
        //or is the second character like in C: windows path
        if (-1 == location.indexOf(':') || 1 == location.indexOf(':')) {
            URL url = Thread.currentThread().getContextClassLoader().getResource(location);
            if (url == null) {
                location = new StringBuffer(FILE_URL_PREFIX).append(location).toString();
            } else {
                location = url.toString();
            }
        }

        //remove trailing space character
        location = location.trim();
        URI uri;
        try {

            uri = new URI(null, null, null, -1, location, null, null);
        } catch (URISyntaxException ex) {
            logger.error("location cannot be converted to an URI path " + ex.getMessage(), ex);
            throw new IllegalArgumentException("location cannot be converted to an URI path " + ex.getMessage(), ex);
        }


        if (logger.isDebugEnabled()) {
            logger.debug("location=" + location);
        }
        return uri.toString();
    }

    public static void write(String fileLocation, Document document) throws IOException {
        String resolvedLocation = resolveLocation(fileLocation);
        XMLUtils.write(new URL(resolvedLocation), document);
    }

    /**
     * write the updated configuration to the XML file in the UTF-8 format.
     *
     * @param url      URL of the file to write
     * @param document dom4j Document
     * @throws IOException
     */
    public static void write(URL url, Document document) throws IOException {
        OutputFormat outFormat = OutputFormat.createPrettyPrint();
        if (document.getXMLEncoding() != null) {
            outFormat.setEncoding(document.getXMLEncoding());
        } else {
            outFormat.setEncoding(UTF_8);
        }
        XMLWriter out = new XMLWriter(new BufferedOutputStream(new FileOutputStream(url.getPath())), outFormat);
        out.write(document);
        out.flush();
        out.close();
    }

    /**
     * remove in the ascendants elements all the <i>principalRef</i> references with the name of the
     * principal.
     *
     * @param root      DOM4J Element of the document
     * @param principal
     */
    public static void deletePrincipalRefs(Element root, RolePrincipal principal) {
        Element principalsElement = root.element(PRINCIPALS);
        List principalsRefList = principalsElement.selectNodes(PRINCIPAL_REF_NAME_REGEXP + principal.getLocalName() + "']");
        for (Object aPrincipalsRefList : principalsRefList) {
            Element principalRef = (Element) aPrincipalsRefList;
            Element principalElement = principalRef.getParent();
            principalElement.remove(principalRef);
            if (principalElement.elements(PRINCIPAL_REF).isEmpty()) {
                principalElement.getParent().remove(principalElement);
            }
        }
    }


    private static URL calculateSchemaLocation(URL xmlLocation, String schemaName) {
        String externalForm = xmlLocation.toExternalForm();
        String directory = externalForm.substring(0, externalForm.lastIndexOf(SLASH) + 1);
        String schemaLocation = directory + schemaName;
        URL schema;
        try {
            schema = new URL(schemaLocation);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e);
        }
        return schema;
    }
}
