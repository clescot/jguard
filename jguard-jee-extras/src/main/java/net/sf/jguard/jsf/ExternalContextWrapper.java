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
package net.sf.jguard.jsf;

import javax.faces.context.ExternalContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * wrapper used to decorate the ExternalContext.
 * it can be compared to the <i>HttpServletRequestWrapper</i> class.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class ExternalContextWrapper extends ExternalContext {

    private ExternalContext externalContext;

    public ExternalContextWrapper(ExternalContext context) {
        externalContext = context;
    }

    public void dispatch(String arg0) throws IOException {
        externalContext.dispatch(arg0);
    }

    public String encodeActionURL(String arg0) {
        return externalContext.encodeActionURL(arg0);
    }

    public String encodeNamespace(String arg0) {
        return externalContext.encodeNamespace(arg0);
    }

    public String encodeResourceURL(String arg0) {
        return externalContext.encodeNamespace(arg0);
    }

    public Map getApplicationMap() {
        return externalContext.getApplicationMap();
    }

    public String getAuthType() {
        return externalContext.getAuthType();
    }

    public Object getContext() {
        return externalContext.getContext();
    }

    public String getInitParameter(String arg0) {
        return externalContext.getInitParameter(arg0);
    }

    public Map getInitParameterMap() {
        return externalContext.getInitParameterMap();
    }

    public String getRemoteUser() {
        return externalContext.getRemoteUser();
    }

    public Object getRequest() {
        return externalContext.getRequest();
    }

    public String getRequestContextPath() {
        return externalContext.getRequestContextPath();
    }

    public Map getRequestCookieMap() {
        return externalContext.getRequestCookieMap();
    }

    public Map getRequestHeaderMap() {
        return externalContext.getRequestHeaderMap();
    }

    public Map getRequestHeaderValuesMap() {
        return externalContext.getRequestHeaderValuesMap();
    }

    public Locale getRequestLocale() {
        return externalContext.getRequestLocale();
    }

    public Iterator getRequestLocales() {
        return externalContext.getRequestLocales();
    }

    public Map getRequestMap() {
        return externalContext.getRequestMap();
    }

    public Map getRequestParameterMap() {
        return externalContext.getRequestParameterMap();
    }

    public Iterator getRequestParameterNames() {
        return externalContext.getRequestParameterNames();
    }

    public Map getRequestParameterValuesMap() {
        return externalContext.getRequestParameterValuesMap();
    }

    public String getRequestPathInfo() {
        return externalContext.getRequestPathInfo();
    }

    public String getRequestServletPath() {
        return externalContext.getRequestServletPath();
    }

    public URL getResource(String arg0) throws MalformedURLException {
        return externalContext.getResource(arg0);
    }

    public InputStream getResourceAsStream(String arg0) {
        return externalContext.getResourceAsStream(arg0);
    }

    public Set getResourcePaths(String arg0) {
        return externalContext.getResourcePaths(arg0);
    }

    public Object getResponse() {
        return externalContext.getResponse();
    }

    public Object getSession(boolean arg0) {
        return externalContext.getSession(arg0);
    }

    public Map getSessionMap() {
        return externalContext.getSessionMap();
    }

    public Principal getUserPrincipal() {
        return externalContext.getUserPrincipal();
    }

    public boolean isUserInRole(String arg0) {
        return externalContext.isUserInRole(arg0);
    }

    public void log(String arg0) {
        externalContext.log(arg0);
    }

    public void log(String arg0, Throwable arg1) {
        externalContext.log(arg0, arg1);
    }

    public void redirect(String arg0) throws IOException {
        externalContext.redirect(arg0);
    }

}
