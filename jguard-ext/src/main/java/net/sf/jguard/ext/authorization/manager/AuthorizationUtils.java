/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name$
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
package net.sf.jguard.ext.authorization.manager;

import net.sf.jguard.core.authorization.manager.AuthorizationManager;
import net.sf.jguard.core.authorization.manager.AuthorizationManagerException;
import net.sf.jguard.ext.authentication.manager.XmlAuthenticationManager;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;

/**
 * Utility class dedicated to AuthorizationManager.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @see AuthorizationManager
 */
public class AuthorizationUtils {
    /**
     * create an empty XmlAuthorizationManager, and import the data contained in the source AuthorizationManager
     * into it.
     *
     * @param authorizationManager source owning data
     * @param xmlAuthorizationManagerOptions options to build the XmlAuthorizationManager which will contain data imported
     * @return a new XmlAuthorizationManager containing imported data
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException thrown when the temporary XmlAuthorizationManager is created
     */
    public static XmlAuthorizationManager exportAsXmlAuthorizationManager(AuthorizationManager authorizationManager, Map xmlAuthorizationManagerOptions) throws AuthorizationManagerException {
        XmlAuthorizationManager xmlAuthorizationManager;
        if (authorizationManager instanceof XmlAuthenticationManager) {
            xmlAuthorizationManager = (XmlAuthorizationManager) authorizationManager;

        } else {
            xmlAuthorizationManager = new XmlAuthorizationManager(authorizationManager.getApplicationName(),xmlAuthorizationManagerOptions);
            xmlAuthorizationManager.importAuthorizationManager(authorizationManager);
        }
        return xmlAuthorizationManager;
    }

    /**
     * import data contained in the Source AuthorizationManager, into an XmlAuthorizationManager and convert
     * it into an XML String.
     *
     * @param authorizationManager source
     * @param XmlAuthorizationManagerOptions options to build the XmlAuthorizationManager which will contain data imported
     * @return new XmlAuthorizationManager containing imported data
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException thrown when the temporary XmlAuthorizationManager is created
     */
    public static String exportAsXMLString(AuthorizationManager authorizationManager, Map XmlAuthorizationManagerOptions) throws AuthorizationManagerException {
        XmlAuthorizationManager xmlAuthorizationManager = exportAsXmlAuthorizationManager(authorizationManager, XmlAuthorizationManagerOptions);
        return xmlAuthorizationManager.exportAsXMLString();
    }

    /**
     * import data contained in the Source AuthorizationManager, into an XmlAuthorizationManager and convert
     * it into an HTML stream.
     * @param authorizationManager source
     * @param XmlAuthorizationManagerOptions options to build the XmlAuthorizationManager which will contain data imported
     * @param outputStream stream receiving the resulting HTML.
     * @throws IOException thrown when problem occurs writing into the output stream.
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException thrown when the temporary XmlAuthorizationManager is created
     */
    public static void writeAsHTML(AuthorizationManager authorizationManager, Map XmlAuthorizationManagerOptions, OutputStream outputStream) throws IOException, AuthorizationManagerException {
        XmlAuthorizationManager xmlAuthorizationManager = exportAsXmlAuthorizationManager(authorizationManager, XmlAuthorizationManagerOptions);
        xmlAuthorizationManager.writeAsHTML(outputStream);
    }

    /**
     *
     * @param authorizationManager source
     * @param XmlAuthorizationManagerOptions options to build the XmlAuthorizationManager which will contain data imported
     * @param outputStream stream receiving the resulting XML.
     * @param encodingScheme encoding used to write into the outputStream.
     * @throws IOException thrown when problem occurs writing into the output stream.
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException thrown when the temporary XmlAuthorizationManager is created
     */
    public static void writeAsXML(AuthorizationManager authorizationManager, Map XmlAuthorizationManagerOptions, OutputStream outputStream, String encodingScheme) throws IOException, AuthorizationManagerException {
        XmlAuthorizationManager xmlAuthorizationManager = exportAsXmlAuthorizationManager(authorizationManager, XmlAuthorizationManagerOptions);
        xmlAuthorizationManager.writeAsXML(outputStream, encodingScheme);
    }

    /**
     *
     * @param authorizationManager source
     * @param XmlAuthorizationManagerOptions options to build the XmlAuthorizationManager which will contain data imported
     * @param fileName path of the file containing the exported XML from the AuthorizationManager
     * @throws IOException thrown when problem occurs writing into the output stream.
     * @throws net.sf.jguard.core.authorization.manager.AuthorizationManagerException thrown when the temporary XmlAuthorizationManager is created
     */
    public static void exportAsXMLFile(AuthorizationManager authorizationManager, Map XmlAuthorizationManagerOptions, String fileName) throws IOException, AuthorizationManagerException {
        XmlAuthorizationManager xmlAuthorizationManager = exportAsXmlAuthorizationManager(authorizationManager, XmlAuthorizationManagerOptions);
        xmlAuthorizationManager.exportAsXMLFile(fileName);
    }
}
