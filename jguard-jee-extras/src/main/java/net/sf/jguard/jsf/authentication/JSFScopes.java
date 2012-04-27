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


import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.technology.AbstractScopes;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.portlet.PortletRequest;
import javax.portlet.PortletSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Iterator;


/**
 * Java Server Faces authentication bindings implementation.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class JSFScopes extends AbstractScopes implements StatefulScopes {

    private FacesContext facesContext;

    @Inject
    public JSFScopes(Request<FacesContext> request) {
        super(request);
        this.facesContext = request.get();
    }


    private ExternalContext getExternalContext() {
        return facesContext.getExternalContext();
    }

    public Object getSessionAttribute(String key) {
        return getExternalContext().getSessionMap().get(key);

    }

    public Iterator<String> getSessionAttributeNames() {
        return getExternalContext().getSessionMap().keySet().iterator();
    }

    public void setSessionAttribute(String key, Object value) {
        getExternalContext().getSessionMap().put(key, value);
    }

    public void removeSessionAttribute(String key) {
        getExternalContext().getSessionMap().remove(key);
    }

    public void setApplicationAttribute(String key, Object value) {
        getExternalContext().getApplicationMap().put(key, value);
    }

    public void setRequestAttribute(String key, Object value) {
        getExternalContext().getRequestMap().put(key, value);
    }


    public Object getApplicationAttribute(String key) {
        return getExternalContext().getApplicationMap().get(key);
    }


    public Object getRequestAttribute(String key) {
        return getExternalContext().getRequestMap().get(key);
    }

    public void removeApplicationAttribute(String key) {
        getExternalContext().getApplicationMap().remove(key);
    }


    public void removeRequestAttribute(String key) {
        getExternalContext().getRequestMap().remove(key);
    }


    public void invalidateSession() {

        Object request = getExternalContext().getRequest();
        if (HttpServletRequest.class.isAssignableFrom(request.getClass())) {
            HttpSession session = ((HttpServletRequest) request).getSession();
            if (session != null) {
                session.invalidate();
            }
        } else if (PortletRequest.class.isAssignableFrom(request.getClass())) {
            PortletSession session = ((PortletRequest) request).getPortletSession();
            if (session != null) {
                session.invalidate();
            }
        }
    }


}
