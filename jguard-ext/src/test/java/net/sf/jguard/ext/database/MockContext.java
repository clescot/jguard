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

import javax.naming.*;
import javax.sql.DataSource;
import java.util.Hashtable;
import java.util.Map;


public class MockContext implements Context {

    private static ConnectionFactory connFactory = null;
    private static DataSource mockDataSource = null;

    public MockContext() {
        System.out.println("mockContext");
    }

    public MockContext(Hashtable env) {
        System.out.println("mockContext(env)");
        if (connFactory == null) {
            Map options = DatabaseOptions.getOptions();
            options.remove("JNDI");
            DatabaseOptions.setOptions(options);
            connFactory = DatabaseOptions.getConnectionFactory();
            mockDataSource = new MockdataSource(connFactory);
        }
    }

    public Object lookup(Name name) throws NamingException {
        return connFactory.getConnection();
    }

    public Object lookup(String name) throws NamingException {
        return mockDataSource;
    }

    public void bind(Name name, Object obj) throws NamingException {
        System.out.println("into bind method(Name name, Object obj) ");

    }

    public void bind(String name, Object obj) throws NamingException {
        System.out.println("into bind(String name, Object obj)");

    }

    public void rebind(Name name, Object obj) throws NamingException {
        System.out.println(" into rebind(Name name, Object obj)");

    }

    public void rebind(String name, Object obj) throws NamingException {
        System.out.println("into rebind(String name, Object obj) ");

    }

    public void unbind(Name name) throws NamingException {
        System.out.println("into unbind(Name name)");

    }

    public void unbind(String name) throws NamingException {
        System.out.println("into unbind(String name)");

    }

    public void rename(Name oldName, Name newName) throws NamingException {
        System.out.println("into rename(Name oldName, Name newName)");

    }

    public void rename(String oldName, String newName) throws NamingException {
        System.out.println("into rename(String oldName, String newName)");

    }

    public NamingEnumeration list(Name name) throws NamingException {
        System.out.println("into NamingEnumeration list(Name name)");
        return null;
    }

    public NamingEnumeration list(String name) throws NamingException {
        System.out.println("into  list(String name) ");
        return null;
    }

    public NamingEnumeration listBindings(Name name) throws NamingException {
        System.out.println("into listBindings(Name name)");
        return null;
    }

    public NamingEnumeration listBindings(String name) throws NamingException {
        System.out.println("listBindings");
        return null;
    }

    public void destroySubcontext(Name name) throws NamingException {
        System.out.println("destroySubcontext");

    }

    public void destroySubcontext(String name) throws NamingException {
        System.out.println("destroySubcontext");

    }

    public Context createSubcontext(Name name) throws NamingException {
        System.out.println("createSubcontext");
        return null;
    }

    public Context createSubcontext(String name) throws NamingException {
        System.out.println("createSubcontext");
        return null;
    }

    public Object lookupLink(Name name) throws NamingException {
        return null;
    }

    public Object lookupLink(String name) throws NamingException {
        return null;
    }

    public NameParser getNameParser(Name name) throws NamingException {
        System.out.println("getNameParser");
        return null;
    }

    public NameParser getNameParser(String name) throws NamingException {
        System.out.println("getNameParser2");
        return null;
    }

    public Name composeName(Name name, Name prefix) throws NamingException {
        System.out.println("composeName");
        return null;
    }

    public String composeName(String name, String prefix)
            throws NamingException {
        System.out.println("composeName");
        return null;
    }

    public Object addToEnvironment(String propName, Object propVal)
            throws NamingException {
        System.out.println("addToEnvironment");
        return null;
    }

    public Object removeFromEnvironment(String propName) throws NamingException {
        System.out.println("removeFromEnvironment");
        return null;
    }

    public Hashtable getEnvironment() throws NamingException {
        System.out.println("getEnvironment");
        return null;
    }

    public void close() throws NamingException {
        System.out.println("close");

    }

    public String getNameInNamespace() throws NamingException {
        System.out.println("getNameInNamespace");
        return null;
    }

}
