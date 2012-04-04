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


import com.google.inject.servlet.RequestScoped;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.technology.AbstractScopes;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Collections;
import java.util.Iterator;


/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
@RequestScoped
public class HttpServletScopes extends AbstractScopes<HttpServletRequest, HttpServletResponse> implements StatefulScopes {


    /**
     * Creates a new instance of HttpServletScopes
     *
     * @param request
     * @param response
     */
    @Inject
    public HttpServletScopes(Request<HttpServletRequest> request,
                             Response<HttpServletResponse> response) {
        super(request, response);
    }


    public Object getSessionAttribute(String key) {
        HttpSession session = getSession(true);
        return session.getAttribute(key);
    }

    public Iterator<String> getSessionAttributeNames() {
        return (Collections.list(getSession(true).getAttributeNames())).iterator();
    }

    public void setSessionAttribute(String key, Object value) {
        HttpSession session = getSession(true);
        session.setAttribute(key, value);
    }

    public void removeSessionAttribute(String key) {
        HttpSession session = getSession(true);
        session.removeAttribute(key);
    }

    public void removeApplicationAttribute(String key) {
        ServletContext servletContext = request.get().getSession(true).getServletContext();
        servletContext.removeAttribute(key);
    }

    public void removeRequestAttribute(String key) {
        request.get().removeAttribute(key);
    }

    public void setRequestAttribute(String key, Object value) {
        request.get().setAttribute(key, value);
    }

    public void setApplicationAttribute(String key, Object value) {
        ServletContext servletContext = getServletContext();
        if (servletContext == null) {
            throw new IllegalStateException(" servletContext is null");
        }
        servletContext.setAttribute(key, value);
    }

    public Object getRequestAttribute(String key) {
        return request.get().getAttribute(key);
    }

    public Object getApplicationAttribute(String key) {
        ServletContext servletContext = getServletContext();
        if (servletContext == null) {
            return null;
        }
        return servletContext.getAttribute(key);
    }


    public void invalidateSession() {
        HttpSession session = getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }

    private ServletContext getServletContext() {
        ServletContext servletContext;
        servletContext = request.get().getSession(true).getServletContext();
        return servletContext;
    }

    private HttpSession getSession(boolean createSession) {
        return request.get().getSession(createSession);
    }

    public String getInitApplicationAttribute(String key) {
        return getServletContext().getInitParameter(key);
    }

}
