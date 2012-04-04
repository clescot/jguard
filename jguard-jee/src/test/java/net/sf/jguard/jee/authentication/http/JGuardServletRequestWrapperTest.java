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
package net.sf.jguard.jee.authentication.http;

import com.mycila.testing.junit.MycilaJunitRunner;
import net.sf.jguard.core.PolicyEnforcementPointOptions;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.principals.Organization;
import net.sf.jguard.core.principals.RolePrincipal;
import net.sf.jguard.core.test.JGuardTestFiles;
import net.sf.jguard.jee.JGuardJEETest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.security.Principal;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MycilaJunitRunner.class)
public class JGuardServletRequestWrapperTest extends JGuardJEETest {

    private static final Logger logger = LoggerFactory.getLogger(JGuardServletRequestWrapperTest.class);
    private static final String TEST_USER = "testUser";
    private String configurationLocation;
    private String applicationName = "jguard-struts-example";

    private AuthenticationManager authenticationManager;
    private static final String LOGIN = "login";
    private static final String DUMMY_VALUE = "bla";

    @Before
    public void setUp() throws Exception {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        String jguardAuthentication = JGuardTestFiles.J_GUARD_AUTHENTICATION_XML.getLabel();
        configurationLocation = cl.getResource(jguardAuthentication).toString();
        authenticationManager = mock(AuthenticationManager.class);
        when(authenticationManager.getCredentialId()).thenReturn(LOGIN);
    }

    @Test
    public void testIsUserInRole() {
        HttpServletRequestSimulator request = new HttpServletRequestSimulator();
        HttpSessionSimulator session = new HttpSessionSimulator();
        request.setSession(session);
        ServletContextSimulator context = new ServletContextSimulator();

        context.setAttribute(PolicyEnforcementPointOptions.APPLICATION_NAME.getLabel(), applicationName);
        session.setServletContext(context);
        // Mock subject and principal creation
        Subject subj = new Subject();
        Organization organization = new Organization();
        Principal p1 = new RolePrincipal(TEST_USER, applicationName, organization);
        Principal p2 = new RolePrincipal("testAnotherUser", applicationName, organization);
        subj.getPrincipals().add(p1);
        subj.getPrincipals().add(p2);

        LoginContextWrapperMockImpl loginContextWrapperMock = new LoginContextWrapperMockImpl(applicationName);
        loginContextWrapperMock.setSubject(subj);
        // Putting into session object
        request.getSession().setAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER, loginContextWrapperMock);

        JGuardServletRequestWrapper wrapper = new JGuardServletRequestWrapper(applicationName, authenticationManager, request, loginContextWrapperMock);

        // Testing
        assertTrue(wrapper.isUserInRole(TEST_USER));
        assertTrue(wrapper.isUserInRole("testAnotherUser"));
        assertFalse(wrapper.isUserInRole("testOneMoreUser"));
    }

    @Test
    public void testGetRemoteUser() {
        HttpServletRequestSimulator request = new HttpServletRequestSimulator();

        // Mock subject and credential
        Subject subj = new Subject();
        JGuardCredential login = new JGuardCredential(LOGIN, TEST_USER);
        LoginContextWrapperMockImpl loginContextWrapperMock = new LoginContextWrapperMockImpl(applicationName);
        loginContextWrapperMock.setSubject(subj);

        request.getSession(true).setAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER, loginContextWrapperMock);
        JGuardServletRequestWrapper wrapper = new JGuardServletRequestWrapper(applicationName, authenticationManager, request, loginContextWrapperMock);

        // Testing with public credentials
        subj.getPublicCredentials().add(login);
        assertEquals(TEST_USER, wrapper.getRemoteUser());

        // Testing with private credentials
        subj.getPublicCredentials().clear();
        assertEquals(subj.getPublicCredentials().size(), 0);
        subj.getPrivateCredentials().add(login);
        //login can only be present in the public subject credential set
        assertNull(TEST_USER, wrapper.getRemoteUser());

        // Testing with no valid credential
        Subject invalidSubj = new Subject();
        JGuardCredential invalidCredential = new JGuardCredential(DUMMY_VALUE, DUMMY_VALUE);
        invalidSubj.getPublicCredentials().add(invalidCredential);
        invalidSubj.getPrivateCredentials().add(invalidCredential);
        ((LoginContextWrapperMockImpl) request.getSession().getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER)).setSubject(invalidSubj);
        assertNull(wrapper.getRemoteUser());
    }


}
