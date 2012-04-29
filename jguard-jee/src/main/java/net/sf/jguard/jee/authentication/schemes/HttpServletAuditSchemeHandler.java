package net.sf.jguard.jee.authentication.schemes;

import net.sf.jguard.core.technology.StatefulScopes;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.servlet.http.HttpServletRequest;
import java.util.Locale;
import java.util.Map;


/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletAuditSchemeHandler extends AuditSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter> {
    public HttpServletAuditSchemeHandler(Map<String, String> parameters,
                                         StatefulScopes authenticationBindings) {
        super(parameters, authenticationBindings);
    }

    protected String getRemoteAddress(HttpServletRequestAdapter req) {
        HttpServletRequest request = req.get();
        return request.getRemoteAddr();
    }

    protected String getRemoteHost(HttpServletRequestAdapter req) {
        HttpServletRequest request = req.get();
        return request.getRemoteHost();
    }

    protected Locale getLocale(HttpServletRequestAdapter req) {
        HttpServletRequest request = req.get();
        return request.getLocale();
    }


}
