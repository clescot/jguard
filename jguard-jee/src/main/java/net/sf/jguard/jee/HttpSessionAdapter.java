package net.sf.jguard.jee;

import net.sf.jguard.core.lifecycle.Session;

import javax.servlet.http.HttpSession;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class HttpSessionAdapter implements Session<HttpSession> {
    private HttpSession httpSession;

    public HttpSessionAdapter(HttpSession httpSession) {
        this.httpSession = httpSession;
    }


    public HttpSession get() {
        return httpSession;
    }
}
