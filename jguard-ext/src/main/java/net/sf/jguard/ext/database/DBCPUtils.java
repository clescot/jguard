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

import org.apache.commons.dbcp.BasicDataSource;

import java.util.Map;

public class DBCPUtils {

    public static final String LOGINTIMEOUT = "logintimeout";
    public static final String VALIDATION_QUERY = "validationQuery";
    public static final String TEST_WHILE_IDLE = "testWhileIdle";
    public static final String TIME_BETWEEN_EVICTION_RUNS_MILLIS = "timeBetweenEvictionRunsMillis";
    public static final String TEST_ON_RETURN = "testOnReturn";
    public static final String TEST_ON_BORROW = "testOnBorrow";
    public static final String NUM_TESTS_PER_EVICTION_RUN = "numTestsPerEvictionRun";
    public static final String MAX_OPEN_PREPARED_STATEMENTS = "maxOpenPreparedStatements";
    public static final String MIN_EVICTABLE_IDLE_TIME_MILLIS = "minEvictableIdleTimeMillis";
    public static final String POOL_PREPARED_STATEMENTS = "poolPreparedStatements";
    public static final String MAX_WAIT = "maxWait";
    public static final String INITIAL_SIZE = "initialSize";
    public static final String MIN_IDLE = "minIdle";
    public static final String MAX_IDLE = "maxIdle";
    public static final String MAX_ACTIVE = "maxActive";
    public static final String DEFAULT_TRANSACTION_ISOLATION = "defaultTransactionIsolation";
    public static final String DEFAULT_READ_ONLY = "defaultReadOnly";
    public static final String DEFAULT_CATALOG = "defaultCatalog";
    public static final String DEFAULT_AUTO_COMMIT = "defaultAutoCommit";
    public static final String ACCESS_TO_UNDERLYING_CONNECTION_ALLOWED = "accessToUnderlyingConnectionAllowed";

    /**
     * @param ds1
     * @param opts
     */
    public static void setDatasourceProperties(BasicDataSource ds1, Map opts) {

        boolean accessToUnderlyingConnectionAllowed = Boolean.valueOf((String) opts.get(ACCESS_TO_UNDERLYING_CONNECTION_ALLOWED));
        ds1.setAccessToUnderlyingConnectionAllowed(accessToUnderlyingConnectionAllowed);


        boolean defaultAutoCommit = Boolean.valueOf((String) opts.get(DEFAULT_AUTO_COMMIT));
        ds1.setDefaultAutoCommit(defaultAutoCommit);


        String defaultCatalog = (String) opts.get(DEFAULT_CATALOG);
        if (defaultCatalog != null && !"".equals(defaultCatalog)) {
            ds1.setDefaultCatalog(defaultCatalog);
        }

        boolean defaultReadOnly = Boolean.valueOf((String) opts.get(DEFAULT_READ_ONLY));
        ds1.setDefaultReadOnly(defaultReadOnly);


        String defaultTransactionIsolationStr = (String) opts.get(DEFAULT_TRANSACTION_ISOLATION);
        if (defaultTransactionIsolationStr != null && !"".equals(defaultTransactionIsolationStr)) {
            int defaultTransactionIsolation = Integer.parseInt(defaultTransactionIsolationStr);
            ds1.setDefaultTransactionIsolation(defaultTransactionIsolation);
        }


        String maxActiveStr = (String) opts.get(MAX_ACTIVE);
        if (maxActiveStr != null && !"".equals(maxActiveStr)) {
            int maxActive = Integer.parseInt(maxActiveStr);
            ds1.setMaxActive(maxActive);
        }

        String maxIdleStr = (String) opts.get(MAX_IDLE);
        if (maxIdleStr != null && !"".equals(maxIdleStr)) {
            int maxIdle = Integer.parseInt(maxIdleStr);
            ds1.setMaxIdle(maxIdle);
        }

        String minIdleStr = (String) opts.get(MIN_IDLE);
        if (minIdleStr != null && !"".equals(minIdleStr)) {
            int minIdle = Integer.parseInt(minIdleStr);
            ds1.setMinIdle(minIdle);
        }

        String initialSizeStr = (String) opts.get(INITIAL_SIZE);
        if (initialSizeStr != null && !"".equals(initialSizeStr)) {
            int initialSize = Integer.parseInt(initialSizeStr);
            ds1.setInitialSize(initialSize);
        }

        String maxWaitStr = (String) opts.get(MAX_WAIT);
        if (maxWaitStr != null && !"".equals(maxWaitStr)) {
            long maxWait = Integer.parseInt(maxWaitStr);
            ds1.setMaxWait(maxWait);
        }

        boolean poolPreparedStatements = Boolean.valueOf((String) opts.get(POOL_PREPARED_STATEMENTS));
        ds1.setPoolPreparedStatements(poolPreparedStatements);


        String minEvictableIdleTimeMillisStr = (String) opts.get(MIN_EVICTABLE_IDLE_TIME_MILLIS);
        if (minEvictableIdleTimeMillisStr != null && !"".equals(minEvictableIdleTimeMillisStr)) {
            long minEvictableIdleTimeMillis = Long.parseLong(minEvictableIdleTimeMillisStr);
            ds1.setMinEvictableIdleTimeMillis(minEvictableIdleTimeMillis);
        }

        String maxOpenPreparedStatementsStr = (String) opts.get(MAX_OPEN_PREPARED_STATEMENTS);
        if (maxOpenPreparedStatementsStr != null && !"".equals(maxOpenPreparedStatementsStr)) {
            int maxOpenPreparedStatements = Integer.parseInt(maxOpenPreparedStatementsStr);
            ds1.setMaxOpenPreparedStatements(maxOpenPreparedStatements);
        }

        String numTestsPerEvictionRunStr = (String) opts.get(NUM_TESTS_PER_EVICTION_RUN);
        if (numTestsPerEvictionRunStr != null && !"".equals(numTestsPerEvictionRunStr)) {
            int numTestsPerEvictionRun = Integer.parseInt(numTestsPerEvictionRunStr);
            ds1.setNumTestsPerEvictionRun(numTestsPerEvictionRun);
        }

        boolean testOnBorrow = Boolean.valueOf((String) opts.get(TEST_ON_BORROW));
        ds1.setTestOnBorrow(testOnBorrow);

        boolean testOnReturn = Boolean.valueOf((String) opts.get(TEST_ON_RETURN));
        ds1.setTestOnReturn(testOnReturn);

        String timeBetweenEvictionRunsMillisStr = (String) opts.get(TIME_BETWEEN_EVICTION_RUNS_MILLIS);
        if (timeBetweenEvictionRunsMillisStr != null && !"".equals(timeBetweenEvictionRunsMillisStr)) {
            long timeBetweenEvictionRunsMillis = Integer.parseInt(timeBetweenEvictionRunsMillisStr);
            ds1.setMaxWait(timeBetweenEvictionRunsMillis);
        }

        boolean testWhileIdle = Boolean.valueOf((String) opts.get(TEST_WHILE_IDLE));
        ds1.setTestWhileIdle(testWhileIdle);


        String validationQuery = (String) opts.get(VALIDATION_QUERY);
        if (validationQuery != null && !"".equals(validationQuery)) {
            ds1.setValidationQuery(validationQuery);
        }

        String logintimeoutStr = (String) opts.get(LOGINTIMEOUT);
        if (logintimeoutStr != null && !"".equals(logintimeoutStr)) {
            int logintimeout = Integer.parseInt(logintimeoutStr);
            ds1.setMaxOpenPreparedStatements(logintimeout);
        }
    }
}
