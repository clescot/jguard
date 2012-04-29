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

package net.sf.jguard.jee.authentication.schemes;

import net.sf.jguard.jee.HttpConstants;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;
import net.sf.jguard.jee.JGuardJEETest;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletLoginPasswordFormSchemeHandlerTest extends JGuardJEETest {

    public static final String AUTHENTICATION_FAILED_JSP = "/authenticationFailed.jsp";
    public static final String AUTHENTICATION_SUCCEED_JSP = "/authenticationSucceed.jsp";


    @Test(expected = IllegalArgumentException.class)
    public void testHandleSchemeCallbacksWithLoginAndPasswordNull() throws UnsupportedCallbackException {
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put(HttpServletLoginPasswordFormSchemeHandler.LOGIN_FIELD, "login");
        parameters.put(HttpServletLoginPasswordFormSchemeHandler.PASSWORD_FIELD, "password");
        parameters.put(HttpServletLoginPasswordFormSchemeHandler.AUTHENTICATION_SUCCEED_URI, AUTHENTICATION_SUCCEED_JSP);
        parameters.put(HttpServletLoginPasswordFormSchemeHandler.AUTHENTICATION_FAILED_URI, AUTHENTICATION_FAILED_JSP);
        parameters.put(HttpServletLoginPasswordFormSchemeHandler.LOGON_PROCESS_URI, "/logonProcess.do");
        parameters.put(HttpConstants.LOGON_URI, "/logon.do");
        parameters.put(HttpConstants.LOGOFF_URI, "/logoff.do");

        HttpServletLoginPasswordFormSchemeHandler schemeHandler = new HttpServletLoginPasswordFormSchemeHandler(parameters);
        HttpServletRequestAdapter request = mock(HttpServletRequestAdapter.class);
        when(request.get()).thenReturn(httpServletRequest);
        HttpServletResponseAdapter response = mock(HttpServletResponseAdapter.class);

        when(response.get()).thenReturn(httpServletResponse);
        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("login");
        callbacks[1] = new PasswordCallback("password", true);
        schemeHandler.handleSchemeCallbacks(request, response, callbacks);
        Assert.assertEquals(AUTHENTICATION_FAILED_JSP, httpServletResponse.getForwardedUrl());

    }


}
