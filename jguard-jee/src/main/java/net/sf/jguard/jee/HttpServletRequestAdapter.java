package net.sf.jguard.jee;

import com.google.inject.servlet.RequestScoped;
import net.sf.jguard.core.lifecycle.StatefulRequest;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Collections;
import java.util.Iterator;

/**
 * adapt HttpServlet technology to the Request interface.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
@RequestScoped
public class HttpServletRequestAdapter implements StatefulRequest<HttpServletRequest> {

    private HttpServletRequest httpServletRequest;

    @Inject
    public HttpServletRequestAdapter(HttpServletRequest httpServletRequest) {

        this.httpServletRequest = httpServletRequest;
    }

    public HttpServletRequest get() {
        return httpServletRequest;
    }

    public void setRequestAttribute(String key, Object value) {
        httpServletRequest.setAttribute(key, value);
    }

    public Object getRequestAttribute(String key) {
        return httpServletRequest.getAttribute(key);
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


    public void invalidateSession() {
        HttpSession session = getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }


    private HttpSession getSession(boolean createSession) {
        return httpServletRequest.getSession(createSession);
    }


}
