package net.sf.jguard.jee;

import com.google.inject.servlet.RequestScoped;
import net.sf.jguard.core.lifecycle.Request;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 * adapt HttpServlet technology to the Request interface.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
@RequestScoped
public class HttpServletRequestAdapter implements Request<HttpServletRequest> {

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


}
