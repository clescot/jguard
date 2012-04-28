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

package net.sf.jguard.jsf.authentication.schemes;

import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.schemes.LoginPasswordFormSchemeHandler;
import net.sf.jguard.core.authorization.filters.LastAccessDeniedFilter;
import net.sf.jguard.core.authorization.permissions.PermissionFactory;
import net.sf.jguard.core.technology.StatefulScopes;
import net.sf.jguard.jee.HttpConstants;
import net.sf.jguard.jsf.FacesContextAdapter;
import net.sf.jguard.jsf.permissions.JSFPermission;
import net.sf.jguard.jsf.permissions.JSFPermissionFactory;
import org.slf4j.LoggerFactory;

import javax.faces.application.NavigationHandler;
import javax.faces.component.UIViewRoot;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.security.auth.Subject;
import java.security.Permission;
import java.util.Map;

/**
 * implements an HTTP FORM Authentication scheme based on the JSF API.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class JSFLoginPasswordFormSchemeHandler extends LoginPasswordFormSchemeHandler<FacesContextAdapter, FacesContextAdapter> {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(JSFLoginPasswordFormSchemeHandler.class.getName());
    private String authenticationSucceedView;
    private String logonView;
    private JSFPermission authenticationSucceedPermission;
    private JSFPermission authenticationFailedPermission;
    private JSFPermission logonPermission;


    @Inject
    public JSFLoginPasswordFormSchemeHandler(Map<String, String> parameters,
                                             StatefulScopes authenticationBindings) {
        super(parameters, authenticationBindings);
        authenticationSucceedView = parameters.get(HttpConstants.AUTHENTICATION_SUCCEED_URI);
        authenticationSucceedPermission = new JSFPermission(authenticationSucceedView);
        authenticationFailedPermission = new JSFPermission(parameters.get(HttpConstants.AUTHENTICATION_FAILED_URI));
        logonView = parameters.get(HttpConstants.LOGON_URI);
        logonPermission = new JSFPermission(logonView);
        String logonProcessURI = parameters.get(HttpConstants.LOGON_PROCESS_URI);
        logonProcessPermission = new JSFPermission(logonProcessURI);
        String logoffURI = parameters.get(HttpConstants.LOGOFF_URI);
        logoffPermission = new JSFPermission(logoffURI);
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
    protected PermissionFactory<FacesContextAdapter> getPermissionFactory() {
        return new JSFPermissionFactory();
    }

    /**
     * redirect to the logonURI JSF view.
     *
     * @throws AuthenticationException
     */
    public void buildChallenge(FacesContextAdapter request, FacesContextAdapter response) {
        redirect(request.get(), logonView);
    }

    /**
     * redirect to the authenticationFailedURI JSF view.
     *
     * @throws AuthenticationException
     */
    public void authenticationFailed(FacesContextAdapter request, FacesContextAdapter response) {
        //an URL for authentication failure event has been set
        if (authenticationFailedPermission != null && !authenticationFailedPermission.getName().equals("")) {
            redirect(request.get(), authenticationFailedPermission.getName());
            logger.debug("authentication failed redirect to " + authenticationFailedPermission.getName());

        } else {
            throw new AuthenticationException("authenticationFailedPermission is null or empty ");
        }
    }

    private void redirect(FacesContext facesContext, String outcome) {
        NavigationHandler nh = facesContext.getApplication().getNavigationHandler();
        nh.handleNavigation(facesContext, null, outcome);
    }

    /**
     * if <i>goToLastAccessprotected void initSettings(Map<String, String> parameters) throws IllegalArgumentException {DeniedUriOnSuccess</i> is set to <b>true</b>,
     * we redirect to the last JSF view which access has been denied.
     * if <i>goToLastAccessDeniedUriOnSuccess</i> is set to <b>false</b>,
     * we redirect to the <i>indexURI</i> if access is granted to it,
     * otherwise to <i>logon</i> JSF view.
     */
    public void authenticationSucceed(Subject subject, FacesContextAdapter request, FacesContextAdapter response) {
        String redirectOutcome = authenticationSucceedView;
        String lastAccessDeniedView = null;
        Permission lastAccessDeniedPermission = (Permission) ((StatefulScopes) statefulScopes).getSessionAttribute(LastAccessDeniedFilter.LAST_ACCESS_DENIED_PERMISSION);
        if (lastAccessDeniedPermission != null) {
            lastAccessDeniedView = lastAccessDeniedPermission.getName();
        }


        //we redirect to the last 'access denied' URI before authentication
        if (lastAccessDeniedView != null && !"".equals(lastAccessDeniedView) && goToLastAccessDeniedUriOnSuccess) {
            redirectOutcome = lastAccessDeniedView;
        } else {
            //redirect to lastAccessDeniedURI is not a wanted mechanism
            //=> we redirect to the authenticationSuccceedURI if access is granted
            //otherwise, we redirect to logonURI
            try {
                //accessControllerWrapper.checkPermission(subject, authenticationSucceedPermission);
                logger.debug(" user is authenticated ", " redirect to " + redirectOutcome);
            } catch (Exception ex) {
                redirectOutcome = logonView;
            }
        }
        FacesContext facesContext = request.get();
        UIViewRoot view = facesContext.getApplication().getViewHandler().createView(facesContext, redirectOutcome);
        facesContext.setViewRoot(view);
        redirect(request.get(), redirectOutcome);

    }

    protected String getLogin(FacesContextAdapter request) {
        Map parameters = request.get().getExternalContext().getRequestParameterMap();
        return (String) parameters.get(LOGIN);
    }

    protected String getPassword(FacesContextAdapter request) {
        Map parameters = request.get().getExternalContext().getRequestParameterMap();
        return (String) parameters.get(PASSWORD);
    }


}
