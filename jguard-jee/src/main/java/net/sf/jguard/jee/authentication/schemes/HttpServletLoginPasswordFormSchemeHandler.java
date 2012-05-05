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
package net.sf.jguard.jee.authentication.schemes;

import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.schemes.LoginPasswordFormSchemeHandler;
import net.sf.jguard.core.authorization.filters.LastAccessDeniedFilter;
import net.sf.jguard.core.authorization.permissions.PermissionFactory;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.jee.HttpConstants;
import net.sf.jguard.jee.HttpPermissionFactory;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Permission;
import java.util.Map;

/**
 * implements an HTTP FORM Authentication scheme based on an HttpServlet API.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletLoginPasswordFormSchemeHandler extends LoginPasswordFormSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter> {


    private String loginField;
    private String passwordField;
    private String authenticationSucceedURI;
    private String logonProcessURI;
    private URLPermission logonProcessPermission;
    private URLPermission logonPermission;
    private String logoffURI;
    private URLPermission logoffPermission;


    private static final Logger logger = LoggerFactory.getLogger(HttpServletLoginPasswordFormSchemeHandler.class.getName());
    private URLPermission authenticationSucceedPermission;
    private URLPermission authenticationFailedPermission;
    public static final String LOGON_PROCESS_URI = "logonProcessURI";
    public static final String LOGIN_FIELD = "loginField";
    public static final String PASSWORD_FIELD = "passwordField";
    public static final String AUTHENTICATION_SUCCEED_URI = "authenticationSucceedURI";
    public static final String AUTHENTICATION_FAILED_URI = "authenticationFailedURI";

    public HttpServletLoginPasswordFormSchemeHandler(Map<String, String> parameters
    ) {
        super(parameters);
        this.loginField = parameters.get(LOGIN_FIELD);
        this.passwordField = parameters.get(PASSWORD_FIELD);

        //authenticationSucceedURI
        this.authenticationSucceedURI = parameters.get(AUTHENTICATION_SUCCEED_URI);
        if (authenticationSucceedURI == null && "".equals(authenticationSucceedURI)) {
            throw new IllegalArgumentException("authenticationSucceedURI parameter is null but is required to instantiate HttpServletLoginPasswordFormSchemeHandler");
        }
        this.authenticationSucceedPermission = new URLPermission(HttpConstants.AUTHENTICATION_SUCCEED_URI, authenticationSucceedURI);

        //authenticationFailedURI
        String authenticationFailedURI = parameters.get(AUTHENTICATION_FAILED_URI);
        if (authenticationFailedURI == null || "".equals(authenticationFailedURI)) {
            throw new IllegalArgumentException("authenticationFailedURI parameter is null but is required to instantiate HttpServletLoginPasswordFormSchemeHandler");
        }
        this.authenticationFailedPermission = new URLPermission(HttpConstants.AUTHENTICATION_FAILED_URI, authenticationFailedURI);

        //logonProcessURI
        logonProcessURI = parameters.get(LOGON_PROCESS_URI);
        if (logonProcessURI == null || "".equals(logonProcessURI)) {
            throw new IllegalArgumentException("logonProcessURI parameter is null but is required to instantiate HttpServletLoginPasswordFormSchemeHandler");
        }
        logonProcessPermission = new URLPermission(LOGON_PROCESS_URI, logonProcessURI);

        //logonURI
        String logonURI = parameters.get(HttpConstants.LOGON_URI);
        if (logonURI == null || "".equals(logonURI)) {
            throw new IllegalArgumentException("logonURI parameter is null but is required to instantiate HttpServletLoginPasswordFormSchemeHandler");
        }
        logonPermission = new URLPermission(HttpConstants.LOGON_URI, logonURI);


        //logoffURI
        logoffURI = parameters.get(HttpConstants.LOGOFF_URI);
        if (logoffURI == null || "".equals(logoffURI)) {
            throw new IllegalArgumentException("logoffURI parameter is null but is required to instantiate HttpServletLoginPasswordFormSchemeHandler");
        }
        logoffPermission = new URLPermission(HttpConstants.LOGOFF_URI, logoffURI);
        buildGrantedPermissions();
    }


    /**
     * @return Permission bound to the FORM target.
     */
    protected Permission getLogonProcessPermission() {
        return logonProcessPermission;
    }

    public Permission getLogoffPermission() {
        return logoffPermission;
    }

    public Permission getLogonPermission() {
        return logonPermission;
    }

    /**
     * return the PermissionFactory.
     *
     * @return
     */
    protected PermissionFactory<HttpServletRequestAdapter> getPermissionFactory() {
        return new HttpPermissionFactory();
    }

    private void handleDispatch(HttpServletRequest request, HttpServletResponse response, URLPermission permission) {

        if (response.isCommitted()) {
            logger.warn("response is already committed");
            return;
        }
        if (URLPermission.FORWARD.equals(permission.getDispatch())) {
            try {
                request.getRequestDispatcher(permission.getURI()).forward(request, response);
            } catch (ServletException ex) {
                logger.error(ex.getMessage(), ex);
                throw new AuthenticationException(ex);
            } catch (IOException ex) {
                logger.error(ex.getMessage(), ex);
                throw new AuthenticationException(ex);
            }
        } else {
            try {
                response.sendRedirect(response.encodeRedirectURL(request.getContextPath() + permission.getURI()));
            } catch (IOException ex) {
                logger.error(ex.getMessage(), ex);
                throw new AuthenticationException(ex);
            }
        }

    }


    public void buildChallenge(HttpServletRequestAdapter req, HttpServletResponseAdapter res) {
        HttpServletRequest request = req.get();
        HttpServletResponse response = res.get();
        handleDispatch(request, response, logonPermission);
    }


    /**
     * translate in the underlying technology the overall authentication success.
     *
     * @param subject
     * @param servletRequest
     * @param servletResponse
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    public void authenticationSucceed(Subject subject, HttpServletRequestAdapter servletRequest, HttpServletResponseAdapter servletResponse) {
        HttpServletRequest request = servletRequest.get();
        HttpServletResponse response = servletResponse.get();
        URLPermission lastAccessDeniedPermission = (URLPermission) servletRequest.getSessionAttribute(LastAccessDeniedFilter.LAST_ACCESS_DENIED_PERMISSION);

        if (!goToLastAccessDeniedUriOnSuccess) {
            handleDispatch(request, response, logonPermission);
        } else if (lastAccessDeniedPermission == null) {
            handleDispatch(request, response, authenticationSucceedPermission);
            request.getSession(true).setAttribute(HttpConstants.GO_TO_LAST_ACCESS_DENIED_URI_ON_SUCCESS, Boolean.TRUE.toString());
        } else if (lastAccessDeniedPermission != null) {
            handleDispatch(request, response, lastAccessDeniedPermission);
            request.getSession(true).setAttribute(HttpConstants.GO_TO_LAST_ACCESS_DENIED_URI_ON_SUCCESS, Boolean.TRUE.toString());
        }

    }


    public void authenticationFailed(HttpServletRequestAdapter req, HttpServletResponseAdapter res) {
        HttpServletRequest request = req.get();
        HttpServletResponse response = res.get();
        //an URL for authentication failure event has been set
        if (authenticationFailedPermission != null && !authenticationFailedPermission.getURI().equals("")) {
            handleDispatch(request, response, authenticationFailedPermission);
            logger.info(" user is not authenticated  and dispatched to " + request.getContextPath() + authenticationFailedPermission.getURI());

        }
    }

    @Override
    protected String getLogin(HttpServletRequestAdapter req) {
        HttpServletRequest request = req.get();
        return request.getParameter(loginField);
    }

    @Override
    protected String getPassword(HttpServletRequestAdapter req) {
        HttpServletRequest request = req.get();
        return request.getParameter(passwordField);
    }


}
