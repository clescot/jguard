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

package net.sf.jguard.ext.database;

import net.sf.jguard.ext.SecurityConstants;
import org.apache.commons.dbcp.BasicDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;


/**
 * Factory for Database Connection.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @version $Revision: 3850 $
 */
public final class ConnectionFactory {
    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(ConnectionFactory.class.getName());

    private String driverClassName = null;
    private String url = null;
    private String login = null;
    private String password = null;

    /**
     * key string which contains applicationName, and, if this application is "secured" (in a jGuard notion),
     * "|" and the applicationPassword
     */
    private String key = null;

    private short mode = 0;
    private final static short DRIVER = 0;
    private final static short JNDI = 1;
    private final static short DATASOURCE = 2;
    //Map which contains Datasources ans connection informations
    //(when the connection is reach through the driverManager)
    private Map connMap = new HashMap();
    private DataSource datasource = null;


    /**
     * inject the Datasource with this constructor.
     * that's the IoC way.
     */
    public ConnectionFactory(DataSource dataSource) {
        this.datasource = dataSource;
        mode = ConnectionFactory.DATASOURCE;
    }

    /**
     * initialise connection settings for the specified webapp in the map (with the <strong>applicationName</strong> parameter).
     *
     * @param opts
     */
    public ConnectionFactory(Map<String,String> opts) {

        logger.debug(" ConnectionFactoryOptions=" + opts);


        //JNDI way
        String jndiRef = opts.get("JNDI");
        if (jndiRef != null) {

            try {
                Hashtable env = new Hashtable(opts);
                InitialContext initCtx = new InitialContext(env);
                Object object = initCtx.lookup(jndiRef);
                if (object instanceof DataSource) {
                    datasource = (DataSource) object;
                } else {
                    throw new IllegalArgumentException(" JNDI lookup " + jndiRef + " must return an object of type javax.sql.DataSource ");
                }
                connMap.put(key, datasource);
                mode = ConnectionFactory.JNDI;
            } catch (NamingException e) {
                if (logger.isDebugEnabled()) {
                    logger.debug("init() -  datasource cannot be retrieved through JNDI "
                            + e.getMessage());
                }
            } catch (Throwable t) {
                logger.error(t.getMessage());
            }

        } else {
            //DriverManager way
            driverClassName = opts.get(SecurityConstants.DATABASE_DRIVER);
            url = opts.get(SecurityConstants.DATABASE_DRIVER_URL);
            login = opts.get(SecurityConstants.DATABASE_DRIVER_LOGIN);
            password = opts.get(SecurityConstants.DATABASE_DRIVER_PASSWORD);
            if (password == null) {
                password = "";
            }
            datasource = getDataSource(driverClassName, url, login, password, opts);

            mode = ConnectionFactory.DRIVER;
        }

    }

    /**
     * Returns a database connection.
     * Connection is pooled with DBCP when url,driver,login and password are set;
     * otherwise, datasource is grabbed either with the injected Datasource (passe in the constructor),
     * or via JNDI where the application server should have  pooled it.
     *
     * @return java.sql.Connection obtained either from a pool or explicitly
     */
    public Connection getConnection() {
        Connection conn = null;

        //jndi stuff
        if (mode == ConnectionFactory.JNDI) {
            conn = getConnectionWithDataSource();
            //driver manager stuff
        } else if (mode == ConnectionFactory.DATASOURCE) {
            conn = getConnectionWithDataSource();
        } else {
            conn = getConnectionWithDriver();
        }
        return conn;


    }


    /**
     * get a connection grabbed through a Datasource reached by JNDI.
     *
     * @return Connection
     * @see javax.sql.DataSource
     */
    private Connection getConnectionWithDataSource() {
        Connection conn = null;
        try {
            conn = datasource.getConnection();
        } catch (SQLException e) {
            logger.error("getConnection() - connection through JNDI cannot be established "
                    + e.getMessage());

        }
        return conn;
    }

    /**
     * get a connection (pooled with DBCP) with some DriverManager parameters.
     *
     * @return Connection
     * @see java.sql.Driver
     */
    private Connection getConnectionWithDriver() {
        Connection conn = null;
        try {
            conn = datasource.getConnection();

        } catch (SQLException e) {
            logger.error("getConnection() - SQLException " + e.getMessage());
            logger.error("getConnection() - SQLException state=" + e.getSQLState());
            logger.error("getConnection() - SQLException error code=" + e.getErrorCode());
            logger.error("getConnection() - SQLException error next exception=" + e.getNextException());
            logger.error("getConnection(String, boolean)", e);
        }
        return conn;
    }


    private DataSource getDataSource(String driverClassName, String url, String login, String password, Map<String,String> options) {
        //DBCP pooled Datasource
        BasicDataSource ds = new BasicDataSource();
        ds.setDriverClassName(driverClassName);
        ds.setUsername(login);
        ds.setPassword(password);
        ds.setUrl(url);

        if (!options.containsKey(DBCPUtils.DEFAULT_AUTO_COMMIT)) {
            options.put(DBCPUtils.DEFAULT_AUTO_COMMIT, "true");
        }
        //set DBCP-related properties
        DBCPUtils.setDatasourceProperties(ds, options);

        return ds;
    }


}
