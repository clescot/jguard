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
package net.sf.jguard.jee;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.mycila.testing.junit.MycilaJunitRunner;
import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.AuthorizationFilter;
import net.sf.jguard.core.enforcement.PolicyEnforcementPoint;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.test.JGuardTestFiles;
import net.sf.jguard.jee.authentication.http.JGuardServletRequestWrapper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

@RunWith(MycilaJunitRunner.class)
public class PolicyEnforcementPointTest extends JGuardJEETest {

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    private static final String WELCOME_DO = "/Welcome.do";

    LoginContextWrapper loginContextWrapper;
    HttpServletRequestAdapter requestAdapter;
    HttpServletResponseAdapter responseAdapter;
    AuthenticationManager authenticationManager;
    Injector injector;
    List<AuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>> authenticationFilters;
    List<AuthorizationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>> authorizationFilters;
    javax.servlet.FilterChain filterChain = new MockFilterChain();
    @Inject
    AuthorizationBindings<HttpServletRequestAdapter, HttpServletResponseAdapter> authorizationBindings;


    @Before
    public void setUp() throws Exception {
        //forge request
        request = new MockHttpServletRequest();
        request.setContextPath(JGuardTestFiles.JGUARD_STRUTS_EXAMPLE.getLabel());
        request.setMethod("GET");
        request.setScheme("http");
        requestAdapter = new HttpServletRequestAdapter(new JGuardServletRequestWrapper(APPLICATION_NAME, authenticationManager, request, loginContextWrapper));

        //forge response
        response = new MockHttpServletResponse();
        responseAdapter = new HttpServletResponseAdapter(response);
        filterChain = new MockFilterChain();
        authenticationFilters = new ArrayList<AuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>();
        authorizationFilters = new ArrayList<AuthorizationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>();
    }

    private PolicyEnforcementPoint getPep(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, javax.servlet.FilterChain filterChain) {
        injector = Guice.createInjector(provideModules(httpServletRequest, httpServletResponse, filterChain));
        return new HttpServletPolicyEnforcementPoint(authenticationFilters, authorizationFilters, propagateThrowable);
    }

    @Test
    public void testPolicyEnforcementPointWithHttpServlet() {
        AuthenticationFilter authenticationFilter = mock(AuthenticationFilter.class);
        authenticationFilters.add(authenticationFilter);
        AuthorizationFilter authorizationFilter = mock(AuthorizationFilter.class);
        authorizationFilters.add(authorizationFilter);
        PolicyEnforcementPoint policyEnforcementPoint = getPep(request, response, filterChain);
        Assert.assertNotNull(policyEnforcementPoint);
    }

    /**
     * we check that the Throwable won't be propagated when propagateTHrowable is set to <b>false</b>.
     */
    @Test
    public void testExceptionWithPropagateThrowableOptionToFalse() {

        propagateThrowable = false;
        injector = Guice.createInjector(provideModules(request, response, filterChain));
        authenticationFilters = new ArrayList<AuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>();

        AuthenticationFilter filter = mock(AuthenticationFilter.class);
        doThrow(new IllegalStateException()).when(filter).doFilter(any(Request.class), any(Response.class), any(FilterChain.class));
        authenticationFilters.add(filter);
        AuthorizationFilter authorizationFilter = mock(AuthorizationFilter.class);
        authorizationFilters.add(authorizationFilter);
        PolicyEnforcementPoint policyEnforcementPoint = getPep(request, response, filterChain);

        request.setRequestURI(WELCOME_DO);

        try {
            policyEnforcementPoint.doFilter(requestAdapter, responseAdapter);
        } catch (Throwable t) {
            Assert.fail(t.getMessage());
        }
        Assert.assertTrue("response status is not 500 but " + response.getStatus(), 500 == response.getStatus());

    }

    /**
     * we check that the Throwable won't be propagated when propagateTHrowable is set to <b>true</b>.
     */
    @Test(expected = IllegalStateException.class)
    public void testExceptionWithPropagateThrowableOptionToTrue() {
        injector = Guice.createInjector(provideModules(request, response, filterChain));
        authenticationFilters = new ArrayList<AuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>>();

        //policyEnforcementPointFilter = injector.getInstance(Key.get(new TypeLiteral<PolicyEnforcementPointFilter<HttpServletRequest, HttpServletResponse>>() {}));
        //filters.add(policyEnforcementPointFilter);
        AuthenticationFilter filter = mock(AuthenticationFilter.class);
        doThrow(new IllegalStateException()).when(filter).doFilter(any(Request.class), any(Response.class), any(FilterChain.class));
        authenticationFilters.add(filter);
        PolicyEnforcementPoint policyEnforcementPoint = getPep(request, response, filterChain);

        request.setRequestURI(WELCOME_DO);
        policyEnforcementPoint.doFilter(requestAdapter, responseAdapter);

    }


}
