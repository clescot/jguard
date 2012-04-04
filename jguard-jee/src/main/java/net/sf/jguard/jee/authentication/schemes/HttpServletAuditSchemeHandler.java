package net.sf.jguard.jee.authentication.schemes;

import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.technology.StatefulScopes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Locale;
import java.util.Map;


/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletAuditSchemeHandler extends AuditSchemeHandler<HttpServletRequest, HttpServletResponse> {
    public HttpServletAuditSchemeHandler(Map<String, String> parameters,
                                         StatefulScopes authenticationBindings) {
        super(parameters, authenticationBindings);
    }

    protected String getRemoteAddress(Request<HttpServletRequest> req) {
        HttpServletRequest request = req.get();
        return request.getRemoteAddr();
    }

    protected String getRemoteHost(Request<HttpServletRequest> req) {
        HttpServletRequest request = req.get();
        return request.getRemoteHost();
    }

    protected Locale getLocale(Request<HttpServletRequest> req) {
        HttpServletRequest request = req.get();
        return request.getLocale();
    }


}
