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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * utility class to create tables, sequences and foreign keys.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class DatabaseUtils {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseUtils.class.getName());

    /**
     * create the missing table, sequences and foreign_keys.
     *
     * @param props            file containing sql queries
     * @param connFactory      connection factory
     *                         jdbc connection
     * @param tablesNames      tables to create
     * @param sequencesNames   sequences to create
     * @param foreignkeysNames foreign keys to create
     */
    public static void createRequiredDatabaseEntities(Properties props, ConnectionFactory connFactory, List sequencesNames,
                                                      List tablesNames, List foreignkeysNames) {

        // we create sequences
        createEntities(props, connFactory, sequencesNames, "SEQUENCE_PRESENCE");

        // we create tables
        createEntities(props, connFactory, tablesNames, "TABLE_PRESENCE");

        // we create foreign keys
        createForeignKeys(props, connFactory, foreignkeysNames);

    }

    private static String handleSensitiveCase(String original, DatabaseMetaData dbMetaData) throws SQLException {
        boolean storesLowerCaseIdentifiers = dbMetaData.storesLowerCaseIdentifiers();
        logger.debug(" database store lower case identifiers =" + storesLowerCaseIdentifiers);
        boolean storesUpperCaseIdentifiers = dbMetaData.storesUpperCaseIdentifiers();
        logger.debug(" database store upper case identifiers =" + storesUpperCaseIdentifiers);
        if (storesLowerCaseIdentifiers) {
            original = original.toLowerCase();
        } else if (storesUpperCaseIdentifiers) {
            original = original.toUpperCase();
        }

        return original;

    }

    private static void createForeignKeys(Properties props, ConnectionFactory connectionFactory, List foreignkeysNames) {
        Connection conn = null;
        try {
            conn = connectionFactory.getConnection();
            DatabaseMetaData dbMetaData = conn.getMetaData();

            for (Object foreignkeysName : foreignkeysNames) {
                String foreignKeyName = (String) foreignkeysName;
                String query = ((String) props.get(foreignKeyName));
                // is there any entity to create?
                // => we check its presence into properties file
                if (query != null) {
                    try {
                        // words have got this structure:
                        // alter table ${FK_TABLE_NAME} add constraint ${CONSTRAINT_NAME} foreign key (${FOREIGN_KEY_COLUMN_NAME})
                        // references ${PRIMARY_KEY_TABLE_NAME}
                        // 0 1 2 3 4 5 6 7 8 9 10
                        // 2,5,8,10 are the only grabbed words
                        List words = Arrays.asList(query.split(" "));
                        /*
                              if (words.size() != 11) {
                                  logger.error(" the query for creating " + foreignKeyName + " must contains 11 words ");
                                  continue;
                              }
                              */
                        String fkTableName = (String) words.get(2);
                        String constraintName = (String) words.get(5);
                        String fKeyColumnName = (String) words.get(8);// remove ()
                        fKeyColumnName = fKeyColumnName.replace('(', ' ');
                        fKeyColumnName = fKeyColumnName.replace(')', ' ').trim();
                        String pKeyTableName = (String) words.get(10);
                        int pKeyIndex = pKeyTableName.indexOf("(");
                        //SQL server include the column when we grab the primary key table name
                        //we remove it
                        if (pKeyIndex > 0) {
                            pKeyTableName = pKeyTableName.substring(0, pKeyIndex);
                        }

                        ResultSet rs = dbMetaData.getImportedKeys(null, null, handleSensitiveCase(fkTableName, dbMetaData));
                        boolean foreignKeyFound = false;
                        while (rs.next()) {
                            logger.debug("importedKeys for=" + fkTableName);
                            String pkeyTableName2 = rs.getString("PKTABLE_NAME");
                            logger.debug("PKTABLE_NAME=" + pkeyTableName2);
                            String pkeyColumnName2 = rs.getString("PKCOLUMN_NAME");
                            logger.debug("PKCOLUMN_NAME=" + pkeyColumnName2);
                            String fkeyTableName2 = rs.getString("FKTABLE_NAME");
                            logger.debug("FKTABLE_NAME=" + fkeyTableName2);
                            String fkeyColumnName2 = rs.getString("FKCOLUMN_NAME");
                            logger.debug("FKCOLUMN_NAME=" + fkeyColumnName2);
                            String constraintName2 = rs.getString("FK_NAME");
                            logger.debug("FK_NAME=" + constraintName2);
                            String pkeyName2 = rs.getString("PK_NAME");
                            logger.debug("PK_NAME=" + pkeyName2);
                            if (fkTableName.equalsIgnoreCase(fkeyTableName2) && fKeyColumnName.equalsIgnoreCase(fkeyColumnName2)
                                    && pKeyTableName.equalsIgnoreCase(pkeyTableName2)
                                    && constraintName.equalsIgnoreCase(constraintName2)) {
                                // foreign key is already present
                                foreignKeyFound = true;
                                break;
                            }

                        }

                        if (foreignKeyFound) {
                            continue;
                        }
                        // we create the entity

                        logger.debug("entity=" + foreignKeyName + " query=" + query);
                        PreparedStatement ps2 = conn.prepareStatement(query);
                        ps2.execute();
                    } catch (SQLException sqle) {
                        logger.error("entity=" + foreignKeyName + " cannot be created . " + sqle.getMessage());
                    }

                } else {
                    logger.info(foreignKeyName + " entry is not present in the properties file ");
                }

            }
        } catch (SQLException e) {
            logger.error(" database metadata cannot be grabbed from the SQL connection ");
        } finally {
            try {
                conn.close();
            } catch (SQLException e) {
                logger.error(" connexion cannot be closed " + e.getMessage());
            }
        }

    }

    /**
     * create database entities (sequences or tables).
     *
     * @param props
     * @param connectionFactory connection Factory
     * @param entitiesNames     tables name which permit to build sequence name
     * @param presenceQueryKey
     */
    private static void createEntities(Properties props, ConnectionFactory connectionFactory, List entitiesNames,
                                       String presenceQueryKey) {
        Connection conn = null;
        String presenceQuery = props.getProperty(presenceQueryKey);
        try {
            conn = connectionFactory.getConnection();
            DatabaseMetaData dbMetaData = conn.getMetaData();
            for (Object entitiesName : entitiesNames) {
                String entityName = (String) entitiesName;

                // is there any entity to create?
                // => we check its presence into properties file
                if (props.get(entityName) != null) {
                    try {
                        // does the entity is already present in the database?
                        String replacedPresenceQuery = presenceQuery.replaceFirst("\\?", handleSensitiveCase(entityName,
                                dbMetaData));
                        PreparedStatement ps1 = conn.prepareStatement(replacedPresenceQuery);
                        logger.debug(replacedPresenceQuery);
                        ResultSet rs1 = ps1.executeQuery();
                        if (rs1.next()) {
                            // entity is already present
                            logger.debug(" entity " + entityName + " has been detected : " + rs1.getObject(1));
                            continue;
                        }
                    } catch (SQLException e) {
                        logger.debug(" entity " + entityName + " does not exists and will be created ");
                    }
                    try {
                        // we create the entity
                        String query2 = (String) props.get(entityName);
                        logger.debug("entity=" + entityName + " query2=" + query2);
                        PreparedStatement ps2 = conn.prepareStatement(handleSensitiveCase(query2, dbMetaData));
                        ps2.execute();
                    } catch (SQLException sqle) {
                        logger.error("entity=" + entityName + " cannot be created . " + sqle.getMessage());
                        throw new RuntimeException(sqle);
                    }

                } else {
                    logger.info(entityName + " entry is not present in the properties file ");
                }

            }
        } catch (SQLException e) {
            logger.error(e.getMessage());
        } finally {
            try {
                conn.close();
            } catch (SQLException e) {
                logger.error(" connexion cannot be closed " + e.getMessage());
            }
        }
    }

    /**
     * detect if the database has got some datas. return <i>true</i> if <strong>all</strong> jGuard tables involved in
     * authorization are empty
     *
     * @param props             properties files containing SQL queries
     * @param connectionFactory connection factory used to check if the database is empty
     * @param selectQueries     queries to execute
     * @return true if the database schema is empty
     */
    public static boolean isEmpty(Properties props, ConnectionFactory connectionFactory, List selectQueries) {
        if (props == null) {
            throw new IllegalArgumentException(" properties is null ");
        }
        if (connectionFactory == null) {
            throw new IllegalArgumentException(" connectionFactory is null ");
        }
        boolean empty = true;
        Connection conn = null;
        try {
            conn = connectionFactory.getConnection();
            PreparedStatement pst = null;
            ResultSet rs = null;
            for (Object selectQuery : selectQueries) {
                try {
                    String key = (String) selectQuery;
                    String query = props.getProperty(key);
                    pst = conn.prepareStatement(query);
                    rs = pst.executeQuery();
                    if (rs.next()) {
                        logger.info(" there are some principals in database ");
                        empty = false;
                        break;
                    }

                } catch (SQLException e) {
                    logger.debug(e.getMessage());
                }
            }
        } finally {
            try {
                conn.close();
            } catch (SQLException e) {
                logger.debug(e.getMessage());
            }
        }
        return empty;
    }

}
