/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name: v080beta1 $
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

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;


public class HttpServletRequestSimulator extends
        com.kizna.servletunit.HttpServletRequestSimulator {

    private HttpSession session = null;
    private Map attributes = null;
    private boolean secure = false;

    public HttpServletRequestSimulator() {
        super();
        attributes = new HashMap();
    }

    public HttpSession getSession() {
        return session;
    }

    public HttpSession getSession(boolean b) {
        if (b && session == null) {
            session = new HttpSessionSimulator();
        }
        return session;
    }

    public void setSession(HttpSession session) {
        this.session = session;
    }

    public Object getAttribute(String attKey) {

        return attributes.get(attKey);
    }

    public Map getParameterMap() {
        return null;
    }

    public void setAttribute(String attKey, Object value) {
        attributes.put(attKey, value);
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }

}
