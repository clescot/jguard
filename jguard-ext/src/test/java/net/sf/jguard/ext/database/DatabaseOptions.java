/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name: v080beta1 $
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
package net.sf.jguard.ext.database;

import junit.framework.TestCase;
import net.sf.jguard.core.PolicyEnforcementPointOptions;
import net.sf.jguard.core.util.FileUtils;
import net.sf.jguard.ext.SecurityConstants;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class DatabaseOptions {
    private static Properties properties = null;
    private static Map options = null;
    private static ConnectionFactory connectionFactory = null;
    private static String propertiesURIPath = null;
    private String database = null;

    public DatabaseOptions() {
        setUp();
    }

    public void setUp() {

        setDatabase(System.getProperty("database"));
        System.out.println("'database' system property=" + getDatabase());
        Properties databaseProperties;
        if (getDatabase() == null || getDatabase().equals("")) {
            setDatabase("h2");
            System.setProperty("database", "h2");
        }
        options = new HashMap();
        databaseProperties = new Properties();
        String databasePropertiesLocation = null;
        if (getDatabase().equals("JNDI")) {
            options.put("JNDI", "java:/comp/env.jguard");
            databasePropertiesLocation = File.separator + "database" + File.separator + "h2.properties";
            options.put(SecurityConstants.INITIAL_CONTEXT_FACTORY, "net.sf.jguard.ext.database.MockInitialContextFactory");

        } else {
            databasePropertiesLocation = "/database/" + getDatabase() + ".properties";
        }

        loadProperties(databaseProperties, databasePropertiesLocation);
        options.put(PolicyEnforcementPointOptions.APPLICATION_NAME.getLabel(), "jGuardExample");
        options.put(SecurityConstants.DATABASE_DRIVER, databaseProperties.get(SecurityConstants.DATABASE_DRIVER));
        options.put(SecurityConstants.DATABASE_DRIVER_URL, databaseProperties.get(SecurityConstants.DATABASE_DRIVER_URL));
        options.put(SecurityConstants.DATABASE_DRIVER_LOGIN, databaseProperties.get(SecurityConstants.DATABASE_DRIVER_LOGIN));
        options.put(SecurityConstants.DATABASE_DRIVER_PASSWORD, databaseProperties.get(SecurityConstants.DATABASE_DRIVER_PASSWORD));
        options.put("importXmlData", "true");
        setConnectionFactory(options);
    }

    private void loadProperties(Properties properties, String propertiesLocation) {
        try {
            URL url = getClass().getResource(propertiesLocation);
            if (url == null) {
                throw new IllegalArgumentException(propertiesLocation + " not found ");
            }
            URI uri = null;
            try {
                uri = new URI(url.toString());
                propertiesURIPath = uri.toString();
            } catch (URISyntaxException e) {
                TestCase.fail(e.getMessage());
                e.printStackTrace();
            }
            File f = FileUtils.getFile(uri);
            properties.load(new FileInputStream(f));
        } catch (FileNotFoundException e) {
            TestCase.fail(" propertiesLocation is not found ");
            e.printStackTrace();
        } catch (IOException e) {
            TestCase.fail(" ioexception ");
            e.printStackTrace();
        }
    }

    public static void setConnectionFactory(Map<String, String> options) {
        connectionFactory = new ConnectionFactory(options);
    }


    public static ConnectionFactory getConnectionFactory() {
        if (connectionFactory == null) {
            setConnectionFactory(options);
        }
        return connectionFactory;
    }

    public static void setConnectionFactory(ConnectionFactory connectionFactory) {
        DatabaseOptions.connectionFactory = connectionFactory;
    }

    public static Map getOptions() {
        return options;
    }

    public static void setOptions(Map options) {
        DatabaseOptions.options = options;
    }

    public static String getPropertiesURIPath() {
        return propertiesURIPath;
    }

    public static void setPropertiesURIPath(String propertiesURL) {
        DatabaseOptions.propertiesURIPath = propertiesURL;
    }

    public String getDatabase() {
        return database;
    }

    public void setDatabase(String database) {
        this.database = database;
    }


}
