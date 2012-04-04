package net.sf.jguard.jee.authentication.http;

import com.octo.captcha.service.CaptchaService;
import net.sf.jguard.ext.SecurityConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
@RunWith(MockitoJUnitRunner.class)
public class AccessFilterAuthenticationWithCaptchaTest extends AccessFilterTest {
    private static final String GET = "GET";
    private static final String CAPTCHA_URI = "/Captcha.do";
    private static final String LOGON_PROCESS_URI = "/LogonProcess.do";

    protected MockHttpSession session;


    @SuppressWarnings({"PublicMethodNotExposedInInterface"})
    @Before
    public void setUp() throws ServletException {

        super.setUp();

    }


    @Test
    public void testAuthenticationWithCaptcha() throws IOException, ServletException {

        //login call
        MockHttpServletRequest requestLogon = new MockHttpServletRequest(context, GET, "/Logon.do");
        session = new MockHttpSession(context, "47");
        requestLogon.setSession(session);
        MockHttpServletResponse responseLogon = new MockHttpServletResponse();
        guiceFilter.doFilter(requestLogon, responseLogon, filterChain);


        //captcha call(the login page reached in response to Logon.do contains a link to a generated image
        //which is the captcha (at the location /Captcha.do)
        MockHttpServletRequest requestCaptchaLogon = new MockHttpServletRequest(context, GET, CAPTCHA_URI);
        requestLogon.setSession(session);
        MockHttpServletResponse responseCaptchaLogon = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
        guiceFilter.doFilter(requestCaptchaLogon, responseCaptchaLogon, filterChain);

        CaptchaChallengeBuilder.buildCaptchaChallenge(requestCaptchaLogon, responseCaptchaLogon);
        CaptchaService service = mock(CaptchaService.class);
        when(service.validateResponseForID("47", "toto")).thenReturn(true);
        //we override the captcha service to return true to the captcha challenge in all cases
        session.getServletContext().setAttribute(SecurityConstants.CAPTCHA_SERVICE, service);

        //logonProcess call
        MockHttpServletRequest requestLogonProcess = new MockHttpServletRequest(context, "POST", LOGON_PROCESS_URI);
        requestLogonProcess.setSession(session);
        requestLogonProcess.addParameter("login", "rick");
        requestLogonProcess.addParameter("password", "dangerous");
        requestLogonProcess.addParameter("captchaAnswer", "toto");
        MockHttpServletResponse responseLogonProcess = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
        guiceFilter.doFilter(requestLogonProcess, responseLogonProcess, filterChain);

    }


}
