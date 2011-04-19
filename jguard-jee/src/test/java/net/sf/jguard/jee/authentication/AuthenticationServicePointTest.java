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
package net.sf.jguard.jee.authentication;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import net.sf.jguard.core.authentication.*;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.technology.ImpersonationScopes;
import net.sf.jguard.core.technology.Scopes;
import net.sf.jguard.core.technology.StatefulScopes;
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

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

/**
 * test AuthenticationServicePoint.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
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
        AuthenticationStatus status = authenticationServicePoint.authenticate(requestAdapter, responseAdapter, callbackHandler).getStatus();

        assertEquals(AuthenticationStatus.FAILURE, status);
        assertEquals(APPLICATION_NAME + "/Logon.do", response.getRedirectedUrl());
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
        AuthenticationStatus status = authenticationServicePoint.authenticate(requestAdapter, responseAdapter, callbackHandler).getStatus();
        assertEquals(AuthenticationStatus.SUCCESS, status);
    }

    /**
     * we test that a successful authentication followed by an impersonation succeed, and does
     * not imply an overwrite of the firstly authenticated user.
     *
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    @Test
    public void testImpersonationAsGuest() throws AuthenticationException {
        testSuccessFulAuthentication();

        injector = Guice.createInjector(provideModules(request, response, filterChain));
        AuthenticationServicePoint<HttpServletRequest, HttpServletResponse> authenticationServicePoint = injector.getInstance(Key.get(new TypeLiteral<AuthenticationServicePoint<HttpServletRequest, HttpServletResponse>>() {
        }));
        ImpersonationScopes impersonationScopes = injector.getInstance(ImpersonationScopes.class);
        Scopes scopes = injector.getInstance(Scopes.class);
        JGuardCallbackHandler callbackHandler = injector.getInstance(JGuardCallbackHandler.class);
        AuthenticationStatus status = authenticationServicePoint.impersonateAsGuest(requestAdapter, responseAdapter, impersonationScopes).getStatus();
        assertEquals(AuthenticationStatus.SUCCESS, status);
        LoginContextWrapperImpl authnUtils2 = (LoginContextWrapperImpl) ((StatefulScopes) scopes).getSessionAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
        LoginContextWrapperImpl authnUtils = (LoginContextWrapperImpl) ((StatefulScopes) scopes).getSessionAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
        Subject adminSubject = authnUtils.getSubject();
        Subject adminSubject2 = authnUtils2.getSubject();
        assertEquals(adminSubject, adminSubject2);
    }


}
