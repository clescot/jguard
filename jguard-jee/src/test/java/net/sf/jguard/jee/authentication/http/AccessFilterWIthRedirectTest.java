package net.sf.jguard.jee.authentication.http;

import net.sf.jguard.core.test.JGuardTestFiles;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AccessFilterWIthRedirectTest extends AccessFilterTest {


    protected static String filterLocation = JGuardTestFiles.J_GUARD_FILTER_WITH_REDIRECT_XML.getLabel();

    @SuppressWarnings({"PublicMethodNotExposedInInterface"})
    @Before
    public void setUp() throws ServletException {
        AccessFilterTest.filterLocation = filterLocation;
        super.setUp();
    }


     /**
     * this test assert that the response will be a redirect to a logon form,
     * and not a 401 HTTP code, because we use a stateful PEP
     */
    @Test
    public void testAccessToUnauthorizedResourceWithNoSubject() {
        request = new MockHttpServletRequest(context, GET, WEIRD_JSP);
        request.setServletPath(WEIRD_JSP);
        response = new MockHttpServletResponse();
        try {
            guiceFilter.doFilter(request, response, filterChain);
            assertTrue("response doesn't contain a redirect url to " + LOGON_DO, LOGON_DO.equals(((MockHttpServletResponse) response).getRedirectedUrl()));
        } catch (Throwable e) {
            fail(e.getMessage());
        }
    }


     @Test
    public void testUnsuccessfulAuthentication() throws IOException, ServletException {
        //get the login FORM
        MockHttpServletRequest request = new MockHttpServletRequest(context, GET, LOGON_DO);
        request.setServletPath(LOGON_DO);
        HttpSession session = new MockHttpSession(context, FIXED_HTTP_SESSION_ID);
        request.setSession(session);
        HttpServletResponse response = new MockHttpServletResponse();
        guiceFilter.doFilter(request, response, filterChain);
        Cookie[] cookies = ((MockHttpServletResponse) response).getCookies();

        //submit authentication credentials through the login FORM
        MockHttpServletRequest requestLogonProcess = new MockHttpServletRequest(context, POST, LOGON_PROCESS_DO);
        requestLogonProcess.setServletPath(LOGON_PROCESS_DO);
        requestLogonProcess.setSession(session);
        requestLogonProcess.addParameter(LOGIN, DUMMY);
        requestLogonProcess.addParameter(PASSWORD, DUMMY);
        MockHttpServletResponse responseLogonProcess = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
        guiceFilter.doFilter(requestLogonProcess, responseLogonProcess, filterChain);
        Cookie[] cookies2 = responseLogonProcess.getCookies();
        assertTrue(HttpServletResponse.SC_OK == responseLogonProcess.getStatus());
        //default dispatch mode is forward.redirect can be set in the permission.
        assertTrue("response must encode a redirect url but " + responseLogonProcess.getRedirectedUrl(),AUTHENTICATION_FAILED.equals(responseLogonProcess.getRedirectedUrl()));

    }


    @Test
       public void testSuccessFulAuthentication() throws IOException, ServletException {
           //get the login FORM
           MockHttpServletRequest request = new MockHttpServletRequest(context, GET, LOGON_DO);
           request.setServletPath(LOGON_DO);
           HttpSession session = new MockHttpSession(context, FIXED_HTTP_SESSION_ID);
           request.setSession(session);
           HttpServletResponse response = new MockHttpServletResponse();
           guiceFilter.doFilter(request, response, filterChain);
           Cookie[] cookies = ((MockHttpServletResponse) response).getCookies();

           //submit authentication credentials through the login FORM
           MockHttpServletRequest requestLogonProcess = new MockHttpServletRequest(context, POST, LOGON_PROCESS_DO);
           requestLogonProcess.setServletPath(LOGON_PROCESS_DO);
           requestLogonProcess.setSession(session);
           requestLogonProcess.addParameter(LOGIN, ADMIN);
           requestLogonProcess.addParameter(PASSWORD, ADMIN);
           MockHttpServletResponse responseLogonProcess = new MockHttpServletResponse();
           filterChain = new MockFilterChain();
           guiceFilter.doFilter(requestLogonProcess, responseLogonProcess, filterChain);
           assertTrue("response status to a logonProcess request is not OK (200) but " + responseLogonProcess.getStatus(), HttpServletResponse.SC_OK == responseLogonProcess.getStatus());
           assertTrue(AUTHENTICATION_SUCCEED.equals(responseLogonProcess.getRedirectedUrl()));
       }

}
