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


package net.sf.jguard.jsf.authorization;

import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.authorization.filters.LastAccessDeniedFilter;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.jsf.ExternalContextUtil;
import net.sf.jguard.jsf.permissions.JSFPermissionFactory;

import javax.faces.application.Application;
import javax.faces.application.FacesMessage;
import javax.faces.application.NavigationHandler;
import javax.faces.context.FacesContext;
import java.security.Permission;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.ResourceBundle;

/**
 * JSF implementation of AuthorizationBindings.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class JSFAuthorizationBindings implements AuthorizationBindings<FacesContext, FacesContext> {

    /**
     * forward to the "accessDenied" view the user and add to the FacesContext with
     * a WARN severity a FaceMessage.
     *
     * @param request
     * @param response
     */
    public void accessDenied(Request<FacesContext> request, Response<FacesContext> response) {
        FacesContext facesContext = request.get();
        String outcomeAccessDenied = "accessDenied";
        NavigationHandler nh = facesContext.getApplication().getNavigationHandler();
        nh.handleNavigation(facesContext, null, outcomeAccessDenied);
        String msg = getLocalizedAndFormattedMessage(facesContext, outcomeAccessDenied, null);
        facesContext.addMessage(outcomeAccessDenied, new FacesMessage(FacesMessage.SEVERITY_WARN, msg, msg));
    }

    public void handlePermission(Request request, Response response, Permission permission) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public Permission getPermissionRequested(Request<FacesContext> request) {
        return new JSFPermissionFactory().getPermission(request);
    }

    public void setLastAccessDeniedPermission(Request<FacesContext> request,
                                              Permission permission) {
        FacesContext facesContext = request.get();
        ExternalContextUtil.setAttribute(facesContext.getExternalContext(), LastAccessDeniedFilter.LAST_ACCESS_DENIED_PERMISSION, permission);
    }

    public Permission getLastAccessDeniedPermission(Request<FacesContext> request) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public Permission getPostAuthenticationPermission(Request<FacesContext> request) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }


    /**
     * return an localized message according to the Locale from the view root,
     * localized with a message key and parameters
     *
     * @param context
     * @param messageKey
     * @param params     can be null
     * @return
     */
    private String getLocalizedAndFormattedMessage(FacesContext context, String messageKey, Object[] params) {
        // this method is inspired from this book excerpt:
        //http://www.onjava.com/pub/a/onjava/excerpt/JSF_chap8/index.html?page=3
        Application application = context.getApplication();
        String messageBundleName = application.getMessageBundle();
        Locale locale = context.getViewRoot().getLocale();
        if (messageBundleName == null || "".equals(messageBundleName)) {
            return "";
        }
        ResourceBundle rb = ResourceBundle.getBundle(messageBundleName, locale);
        String msgPattern = rb.getString(messageKey);
        String msg = msgPattern;
        if (params != null) {
            msg = MessageFormat.format(msgPattern, params);
        }
        return msg;
    }

}
