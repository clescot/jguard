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
package net.sf.jguard.jsf.permissions;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;


/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */

public class JSFPermissionTest {

    private JSFPermission perm1;
    private JSFPermission perm2;
    private JSFPermission perm3;
    private JSFPermission perm4;
    private JSFPermission perm5;
    private JSFPermission perm6;

    @Before
    public void init() {
        perm1 = new JSFPermission("name");
        perm2 = new JSFPermission("name");
        perm3 = new JSFPermission("name*");
        perm4 = new JSFPermission("nameeeee");
        perm5 = new JSFPermission("name.*");
        perm6 = new JSFPermission("namedddde");
    }

    @Test
    public void testEquals() {
        assertTrue(perm1.equals(perm2));
        assertTrue(perm1.equals(perm1));
        assertFalse(perm1.equals(perm3));
        assertFalse(perm3.equals(perm1));
    }

    @Test
    public void testHashCode() {
        assertEquals(perm1.hashCode(), perm2.hashCode());
    }

    @Test
    public void testImplies() {
        assertTrue(perm1.implies(perm2));
        assertTrue(perm3.implies(perm4));
        assertFalse(perm4.implies(perm3));
        assertTrue(perm5.implies(perm6));
        assertTrue(perm3.implies(perm1));
        assertFalse(perm1.implies(perm3));
    }
}
