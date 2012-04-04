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
package net.sf.jguard.jsf.authentication;

import javax.portlet.*;
import javax.servlet.http.HttpServletRequestWrapper;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

/**
 * wrapper to permit to <i>decorate</i> the {@link PortletRequest}
 * like {@link HttpServletRequestWrapper}.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class PortletRequestWrapper implements PortletRequest {

    protected PortletRequest request = null;
    protected String applicationName;

    public PortletRequestWrapper(PortletRequest portletRequest,String applicationName) {
        request = portletRequest;
        this.applicationName = applicationName;
    }

    public Object getAttribute(String arg0) {
        return request.getAttribute(arg0);
    }

    public Enumeration getAttributeNames() {
        return request.getAttributeNames();
    }

    public String getAuthType() {
        return request.getAuthType();
    }

    public String getContextPath() {
        return request.getContextPath();
    }

    public Locale getLocale() {
        return request.getLocale();
    }

    public Enumeration getLocales() {
        return request.getLocales();
    }

    public String getParameter(String arg0) {
        return request.getParameter(arg0);
    }

    public Map getParameterMap() {
        return request.getParameterMap();
    }

    public Enumeration getParameterNames() {
        return request.getParameterNames();
    }

    public String[] getParameterValues(String arg0) {
        return request.getParameterValues(arg0);
    }

    public PortalContext getPortalContext() {
        return request.getPortalContext();
    }

    public PortletMode getPortletMode() {
        return request.getPortletMode();
    }

    public PortletSession getPortletSession() {
        return request.getPortletSession();
    }

    public PortletSession getPortletSession(boolean arg0) {
        return request.getPortletSession(arg0);
    }

    public PortletPreferences getPreferences() {
        return request.getPreferences();
    }

    public Enumeration getProperties(String arg0) {
        return request.getProperties(arg0);
    }

    public String getProperty(String arg0) {
        return request.getProperty(arg0);
    }

    public Enumeration getPropertyNames() {
        return request.getPropertyNames();
    }

    public String getRemoteUser() {
        return request.getRemoteUser();
    }

    public String getRequestedSessionId() {
        return request.getRequestedSessionId();
    }

    public String getResponseContentType() {
        return request.getResponseContentType();
    }

    public Enumeration getResponseContentTypes() {
        return request.getResponseContentTypes();
    }

    public String getScheme() {
        return request.getScheme();
    }

    public String getServerName() {
        return request.getServerName();
    }

    public int getServerPort() {
        return request.getServerPort();
    }

    public Principal getUserPrincipal() {
        return request.getUserPrincipal();
    }

    public WindowState getWindowState() {
        return request.getWindowState();
    }

    public boolean isPortletModeAllowed(PortletMode arg0) {
        return request.isPortletModeAllowed(arg0);
    }

    public boolean isRequestedSessionIdValid() {
        return request.isRequestedSessionIdValid();
    }

    public boolean isSecure() {
        return request.isSecure();
    }

    public boolean isUserInRole(String arg0) {
        return request.isUserInRole(arg0);
    }

    public boolean isWindowStateAllowed(WindowState arg0) {
        return request.isWindowStateAllowed(arg0);
    }

    public void removeAttribute(String arg0) {
        request.removeAttribute(arg0);
    }

    public void setAttribute(String arg0, Object arg1) {
        request.setAttribute(arg0, arg1);
    }

}
