/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.

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
package net.sf.jguard.core.authorization.permissions;

import junit.framework.TestCase;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net ">Charles Gay</a>
 *
 */
public class URLParameterTest extends TestCase {

    public static void main(String[] args) {
    }

    /*
     * @see TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
    }

    /*
     * @see TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Constructor for URLParameter.
     * @param arg0
     */
    public URLParameterTest(String arg0) {
        super(arg0);
    }

    /*
     * Class under test for Object clone()
     */
    public void testClone() {
        URLParameter urlp1 = new URLParameter();
        urlp1.setKey("document");
        String[] value1 = new String[]{"a","b"};
        urlp1.setValue(value1);
        urlp1.setPermissionName("parent");
        URLParameter urlp2 = null;
        try {
            urlp2 = (URLParameter) urlp1.clone();
        } catch (CloneNotSupportedException e) {
            TestCase.fail(e.getMessage());
        }

        assertTrue(urlp2.equals(urlp1));
    }

    /*
     * Class under test for boolean equals(Object)
     */
    public void testEqualsObject() {
        URLParameter urlp1 = new URLParameter();
        urlp1.setKey("document");
        String[] value1 = new String[]{"a","b"};
        urlp1.setValue(value1);
        urlp1.setPermissionName("parent");

        URLParameter urlp2 = new URLParameter();
        urlp2.setKey("document");
        String[] value2 = new String[]{"a","b"};
        urlp2.setValue(value2);
        urlp2.setPermissionName("parent");
        assertTrue(urlp1.equals(urlp2));

        URLParameter urlp3 = new URLParameter();
        urlp3.setKey("toto");
        String[] value3 = new String[]{"a","b"};
        urlp3.setValue(value3);
        urlp3.setPermissionName("parent");
        assertFalse(urlp1.equals(urlp3));

        URLParameter urlp4 = new URLParameter();
        urlp4.setKey("document");
        String[] value4 = new String[]{"b","a"};
        urlp4.setValue(value4);
        urlp4.setPermissionName("parent");
        assertTrue(urlp1.equals(urlp4));

        URLParameter urlp5 = new URLParameter();
        urlp5.setKey("document");
        String[] value5 = new String[]{"a","c"};
        urlp5.setValue(value5);
        urlp5.setPermissionName("parent");
        assertFalse(urlp1.equals(urlp5));
        assertFalse(urlp5.getPermissionName().equals("toto"));
        URLParameter urlp6 = new URLParameter();
         urlp6.setKey("document");
        String[] value6 = new String[]{"a","b,","c"};
         urlp6.setValue(value6);
        assertFalse(urlp6.equals(urlp5));
        assertFalse(urlp5.equals(urlp6));
    }

}
