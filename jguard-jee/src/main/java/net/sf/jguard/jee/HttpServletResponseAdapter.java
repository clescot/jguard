package net.sf.jguard.jee;

import com.google.inject.servlet.RequestScoped;
import net.sf.jguard.core.lifecycle.Response;

import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
@RequestScoped
public class HttpServletResponseAdapter implements Response<HttpServletResponse> {

    private HttpServletResponse httpServletResponse;

    @Inject
    public HttpServletResponseAdapter(HttpServletResponse httpServletResponse) {

        this.httpServletResponse = httpServletResponse;
    }

    public HttpServletResponse get() {
        return httpServletResponse;
    }

}
