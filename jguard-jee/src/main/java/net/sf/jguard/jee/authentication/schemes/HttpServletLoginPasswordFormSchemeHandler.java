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
package net.sf.jguard.jee.authentication.schemes;

import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.authentication.schemes.LoginPasswordFormSchemeHandler;
import net.sf.jguard.core.authorization.filters.LastAccessDeniedFilter;
import net.sf.jguard.core.authorization.permissions.PermissionFactory;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.technology.StatefulScopes;
import net.sf.jguard.jee.HttpConstants;
import net.sf.jguard.jee.HttpPermissionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Permission;
import java.util.Map;

/**
 * implements an HTTP FORM Authentication scheme based on an HttpServlet API.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class HttpServletLoginPasswordFormSchemeHandler extends LoginPasswordFormSchemeHandler<HttpServletRequest, HttpServletResponse> {


    private String loginField;
    private String passwordField;
    private String authenticationSucceedURI;
    private String logonProcessURI;
    private Permission logonProcessPermission;
    private String logonURI;
    private Permission logonPermission;
    private String logoffURI;
    private Permission logoffPermission;


    private static final Logger logger = LoggerFactory.getLogger(HttpServletLoginPasswordFormSchemeHandler.class.getName());
    private URLPermission authenticationSucceedPermission;
    private URLPermission authenticationFailedPermission;
    public static final String LOGON_PROCESS_URI = "logonProcessURI";
    public static final String LOGIN_FIELD = "loginField";
    public static final String PASSWORD_FIELD = "passwordField";
    public static final String AUTHENTICATION_SUCCEED_URI = "authenticationSucceedURI";
    public static final String AUTHENTICATION_FAILED_URI = "authenticationFailedURI";

    public HttpServletLoginPasswordFormSchemeHandler(Map<String, String> parameters,
                                                     StatefulScopes authenticationBindings) {
        super(parameters, authenticationBindings);
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
        logonURI = parameters.get(HttpConstants.LOGON_URI);
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
    protected PermissionFactory<HttpServletRequest> getPermissionFactory() {
        return new HttpPermissionFactory();
    }


    public void buildChallenge(Request<HttpServletRequest> req, Response<HttpServletResponse> res) {
        HttpServletRequest request = req.get();
        HttpServletResponse response = res.get();
        if (!response.isCommitted()) {
            try {
                response.sendRedirect(response.encodeRedirectURL(request.getContextPath() + logonURI));
            } catch (IOException ex) {
                logger.error(ex.getMessage(), ex);
                throw new AuthenticationException(ex);
            }
        }
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
    public void authenticationSucceed(Subject subject, Request<HttpServletRequest> servletRequest, Response<HttpServletResponse> servletResponse) {
        authenticationBindings.setSessionAttribute(AuthenticationSchemeHandler.REDIRECT, "true");
        HttpServletRequest request = servletRequest.get();
        HttpServletResponse response = servletResponse.get();
        String redirectURI = authenticationSucceedURI;
        URLPermission lastAccessDeniedPermission = (URLPermission) authenticationBindings.getSessionAttribute(LastAccessDeniedFilter.LAST_ACCESS_DENIED_PERMISSION);
        String lastAccessDeniedURI;
        if (lastAccessDeniedPermission == null) {
            lastAccessDeniedURI = authenticationSucceedURI;
        } else {
            lastAccessDeniedURI = lastAccessDeniedPermission.getURI();
        }


        //we redirect to the last 'access denied' URI before authentication
        if (lastAccessDeniedURI != null && !"".equals(lastAccessDeniedURI)) {
            if (goToLastAccessDeniedUriOnSuccess) {
                redirectURI = lastAccessDeniedURI;
                request.getSession(true).setAttribute(HttpConstants.GO_TO_LAST_ACCESS_DENIED_URI_ON_SUCCESS, Boolean.TRUE.toString());
            } else {
                redirectURI = logonURI;
            }
        }


        logger.debug(" user is authenticated ", " redirect to " + redirectURI);
        if (!response.isCommitted()) {
            try {
                response.sendRedirect(response.encodeRedirectURL(request.getContextPath() + redirectURI));
            } catch (IOException ex) {
                logger.error(ex.getMessage(), ex);
                throw new AuthenticationException(ex);
            }
        }

    }


    public void authenticationFailed(Request<HttpServletRequest> req, Response<HttpServletResponse> res) {
        authenticationBindings.setSessionAttribute(AuthenticationSchemeHandler.REDIRECT, "true");
        HttpServletRequest request = req.get();
        HttpServletResponse response = res.get();

        if (response.isCommitted()) {
            logger.warn(" response is already committed ");
            return;
        }

        //an URL for authentication failure event has been set
        if (authenticationFailedPermission != null && !authenticationFailedPermission.getURI().equals("")) {
            try {
                response.sendRedirect(response.encodeRedirectURL(request.getContextPath() + authenticationFailedPermission.getURI()));
                logger.debug("authentication failed redirect to " + authenticationFailedPermission.getURI());
            } catch (IOException ex) {
                logger.error(ex.getMessage(), ex);
                throw new AuthenticationException(ex);
            }
            logger.debug(" user is not authenticated  and redirected to " + request.getContextPath() + authenticationFailedPermission.getURI());

        }
    }

    @Override
    protected String getLogin(Request<HttpServletRequest> req) {
        HttpServletRequest request = req.get();
        return request.getParameter(loginField);
    }

    @Override
    protected String getPassword(Request<HttpServletRequest> req) {
        HttpServletRequest request = req.get();
        return request.getParameter(passwordField);
    }


}
