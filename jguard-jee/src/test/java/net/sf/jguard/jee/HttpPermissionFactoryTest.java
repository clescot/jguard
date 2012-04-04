/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2010  Charles Lescot
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * jGuard project home page:
 * http://sourceforge.net/projects/jguard/
 */

package net.sf.jguard.jee;

import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.jee.authentication.http.JGuardServletRequestWrapper;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.security.Permission;

import static org.mockito.Mockito.mock;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpPermissionFactoryTest {
    private static final String APPLICATION_NAME = "jguard-struts-example";
    private MockHttpServletRequest request = null;
    private MockHttpServletResponse response = null;


    private HttpServletRequestAdapter requestAdapter = null;
    private HttpServletResponseAdapter responseAdapter = null;
    private LoginContextWrapper loginContextWrapper;
    private static final String UNAUTHORIZED = "/unauthorized.do";

    @Before
    public void setUp() {
        request = new MockHttpServletRequest();

        //context setup
        request.setContextPath(APPLICATION_NAME);
        AuthenticationManager authenticationmanager = mock(AuthenticationManager.class);

        requestAdapter = new HttpServletRequestAdapter(new JGuardServletRequestWrapper(APPLICATION_NAME,authenticationmanager, request, loginContextWrapper));
        response = new MockHttpServletResponse();
        responseAdapter = new HttpServletResponseAdapter(response);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetPermissionWithWrongArgument() {
        request.setServletPath("/Welcome.do");
        request.setMethod("GET");
        request.setScheme("http");
        request.setRequestURI(APPLICATION_NAME + UNAUTHORIZED);
        HttpPermissionFactory httpPermissionFactory = new HttpPermissionFactory();
        httpPermissionFactory.getPermission(requestAdapter);
    }

    @Test
    public void testGetPermissionWithRightArgument() {
        request.setServletPath(UNAUTHORIZED);
        request.setMethod("GET");
        request.setScheme("http");
        request.setRequestURI(APPLICATION_NAME + UNAUTHORIZED);
        HttpPermissionFactory httpPermissionFactory = new HttpPermissionFactory();
        Permission permission = httpPermissionFactory.getPermission(requestAdapter);
        assert (permission instanceof URLPermission);
    }
}
