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
package net.sf.jguard.ext;

import net.sf.jguard.core.util.FileUtils;
import net.sf.jguard.core.util.XMLUtils;
import net.sf.jguard.ext.database.ConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Properties;

/**
 * Helper class to initialize JdbcManager.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class JdbcManagerHelper {

    public static final String DB_PROPERTIES_LOCATION = "dbPropertiesLocation";
    public static final String CREATE_REQUIRED_DATABASE_ENTITIES = "createRequiredDatabaseEntities";
    public static final String IMPORT_XML_DATA_KEY = "importXmlDataKey";
    public static final String IMP0RT_XML_DATA_VALUE = "importXmlDataValue";
    public static final String XML_FILE_NAME = "xmlFileName";

    private static final Logger logger = LoggerFactory.getLogger(JdbcManagerHelper.class.getName());

    /**
     * create required Database entities (tables, constraints) if needed,
     * and import in empty tables from an XML file optionally too.
     *
     * @param jdbcManager
     * @param connectionFactory
     * @param props
     * @param options
     */
    public static void jdbcInit(JdbcManager jdbcManager, ConnectionFactory connectionFactory, Properties props, Map options) {

        String dbPropertiesLocation = (String) options.get(DB_PROPERTIES_LOCATION);
        String createRequiredDatabaseEntititesStr = (String) options.get(CREATE_REQUIRED_DATABASE_ENTITIES);
        boolean createRequiredDatabaseEntities;
        if (createRequiredDatabaseEntititesStr == null || "".equals(createRequiredDatabaseEntititesStr)) {
            createRequiredDatabaseEntities = true;
        } else {
            createRequiredDatabaseEntities = Boolean.valueOf((String) options.get(CREATE_REQUIRED_DATABASE_ENTITIES));
        }
        String importXmlDataKey = (String) options.get(IMPORT_XML_DATA_KEY);
        boolean importXmlDataValue = Boolean.valueOf((String) options.get(IMP0RT_XML_DATA_VALUE));
        if (dbPropertiesLocation != null && !"".equals(dbPropertiesLocation)) {
            dbPropertiesLocation = XMLUtils.resolveLocation(dbPropertiesLocation);
        } else {
            throw new IllegalArgumentException(" dbPropertiesLocation is null or empty ");
        }
        FileInputStream fileInputStream = null;
        try {
            File file = FileUtils.getFile(new URI(dbPropertiesLocation));
            fileInputStream =new FileInputStream(file);
            props.load(fileInputStream);
            logger.debug(" JdbcManager properties = " + props);
        } catch (FileNotFoundException e2) {
            logger.error(" database properties file is not found at this location " + dbPropertiesLocation);
             logger.error(e2.getMessage(),e2);
        } catch (IOException e2) {
            logger.error(" database properties file is not accesible this location " + dbPropertiesLocation + "\n " + e2.getMessage());
        } catch (URISyntaxException e) {
            logger.error(" uri of the database properties file hasn't got a valid synthax ", e);
        }finally{
            if(fileInputStream!=null){
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

        }

        if (createRequiredDatabaseEntities) {
            jdbcManager.createRequiredDatabaseEntities(props, connectionFactory);
        }
        boolean empty = jdbcManager.isEmpty();
        String XMlFileName = (String) options.get(XML_FILE_NAME);
        String xmlFileLocation = dbPropertiesLocation.substring(0, dbPropertiesLocation.lastIndexOf('/')) + "/" + XMlFileName;
        if (empty && importXmlDataValue) {
            logger.info(" importing XML data into your database from the XML located here:" + xmlFileLocation);
            jdbcManager.insertRequiredData(xmlFileLocation);
        } else if (empty && !importXmlDataValue) {
            logger.warn(" database entities required by jGuard are empty. to fill them with an XML located here :" + xmlFileLocation + "\n  you have to set the JdbcManager (JdbcAuthenticationManager or JdbcAuthorizationManager) option " + importXmlDataKey + " to 'true' ");
        }
    }
}
