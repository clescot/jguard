/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name$
http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles Lescot

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
package net.sf.jguard.jee.authentication;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.AuthenticationStatus;
import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;
import net.sf.jguard.jee.JGuardJEETest;
import net.sf.jguard.jee.authentication.http.JGuardServletRequestWrapper;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

/**
 * test AuthenticationServicePoint.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class AuthenticationServicePointTest extends JGuardJEETest {
    private MockHttpServletRequest request = null;
    private MockHttpServletResponse response = null;
    private MockFilterChain filterChain = null;


    private HttpServletRequestAdapter requestAdapter = null;
    private HttpServletResponseAdapter responseAdapter = null;


    private LoginContextWrapper loginContextWrapper;
    private Injector injector;
    private static final String UNAUTHORIZED = "/unauthorized.do";

    @Before
    public void setUp() throws Exception {
        request = new MockHttpServletRequest();

        //context setup
        request.setContextPath(APPLICATION_NAME);
        filterChain = new MockFilterChain();

        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        requestAdapter = new HttpServletRequestAdapter(new JGuardServletRequestWrapper(APPLICATION_NAME, authenticationManager, request, loginContextWrapper));
        response = new MockHttpServletResponse();
        responseAdapter = new HttpServletResponseAdapter(response);
    }


    /**
     * this method test access to an unauthorized rsource when user is not authenticated.
     * it must response with the authentication challenge.
     * in this situation, the authenticationScheme is FORM, and the challenge is the Logon.do url.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testAccessToUnauthorizedResource() throws Exception {
        MockServletContext context = new MockServletContext();
        context.setServletContextName(APPLICATION_NAME);
        request.setServletPath(UNAUTHORIZED);
        request.setMethod("GET");
        request.setScheme("http");
        request.setRequestURI(APPLICATION_NAME + UNAUTHORIZED);
        injector = Guice.createInjector(provideModules(request, response, filterChain));
        AuthenticationServicePoint<HttpServletRequest, HttpServletResponse> authenticationServicePoint = injector.getInstance(Key.get(new TypeLiteral<AuthenticationServicePoint<HttpServletRequest, HttpServletResponse>>() {
        }));
        JGuardCallbackHandler callbackHandler = injector.getInstance(JGuardCallbackHandler.class);
        AuthenticationStatus status = authenticationServicePoint.authenticate(callbackHandler).getStatus();

        assertEquals(AuthenticationStatus.FAILURE, status);
        assertEquals("/Logon.do", response.getForwardedUrl());
        System.out.println(status);
    }

    /**
     * test a successful authentication.
     *
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    @Test
    public void testSuccessFulAuthentication() throws AuthenticationException {
        request.setMethod("GET");
        request.setScheme("http");
        request.setRequestURI("/LogonProcess.do");
        request.addParameter("login", "admin");
        request.addParameter("password", "admin");
        injector = Guice.createInjector(provideModules(request, response, filterChain));
        AuthenticationServicePoint<HttpServletRequest, HttpServletResponse> authenticationServicePoint = injector.getInstance(Key.get(new TypeLiteral<AuthenticationServicePoint<HttpServletRequest, HttpServletResponse>>() {
        }));
        JGuardCallbackHandler callbackHandler = injector.getInstance(JGuardCallbackHandler.class);
        AuthenticationStatus status = authenticationServicePoint.authenticate(callbackHandler).getStatus();
        assertEquals(AuthenticationStatus.SUCCESS, status);
    }


}
