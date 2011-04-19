/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name: v080_step_2 $
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
import org.junit.Before;
import org.junit.Test;

import java.sql.Connection;
import java.sql.SQLException;

public class ConnectionFactoryTest extends DatabaseOptions {

    @Override
    @Before
    public void setUp() {
        super.setUp();
    }

    /*
    * Test method for 'net.sf.jguard.ext.database.ConnectionFactory.getConnection()'
    */
    @Test
    public void testGetConnection() {
        ConnectionFactory connFactory = getConnectionFactory();
        Connection conn = connFactory.getConnection();
        try {
            System.out.println("driver version " + conn.getMetaData().getDriverVersion());
        } catch (SQLException e) {
            TestCase.fail("  an SQL exception has occured ");
            System.out.println(e.getMessage());
        } finally {
            try {
                conn.close();
            } catch (SQLException e) {
                TestCase.fail("  an SQL exception has occured ");
                System.out.println(e.getMessage());
            }
        }

    }

}
