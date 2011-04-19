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
package net.sf.jguard.core.authorization.permissions;

import junit.framework.TestCase;

import java.net.URISyntaxException;
import java.security.Permission;

public class JGPermissionCollectionTest extends TestCase {


    public void testGetPermission() throws URISyntaxException, NoSuchPermissionException {

        JGPermissionCollection jgperm = new JGPositivePermissionCollection();
        Permission p1 = new URLPermission("mock_perm_1", "http://someuri_1.do?param1=any&param2=bla,description_1");
        Permission p2 = new URLPermission("mock_perm_2", "http://someuri_2.do?param1=any&param2=bla");

        jgperm.add(p1);
        jgperm.add(p2);

        assertEquals(jgperm.getPermission("mock_perm_1"), p1);
        assertEquals(jgperm.getPermission("mock_perm_2"), p2);
        try {
            jgperm.getPermission("some_permission");
            fail("NoSuchPermissionException should be catched");
        } catch (NoSuchPermissionException e) {
        }

    }

    public void testRemovePermission() throws NoSuchPermissionException {

        JGPermissionCollection jgperm = new JGPositivePermissionCollection();
        Permission p = new URLPermission("mock_perm_1");
        jgperm.add(p);

        assertNotNull(jgperm.getPermission("mock_perm_1"));
        jgperm.removePermission(p);
        try {
            jgperm.getPermission("mock_perm_1");
            fail("NoSuchPermissionException should be catched");
        } catch (NoSuchPermissionException e) {
        }

    }


}
