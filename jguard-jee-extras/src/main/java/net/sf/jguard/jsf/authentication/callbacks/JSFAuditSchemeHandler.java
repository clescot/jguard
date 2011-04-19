package net.sf.jguard.jsf.authentication.callbacks;

import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.technology.StatefulScopes;
import net.sf.jguard.jee.authentication.schemes.AuditSchemeHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.faces.context.FacesContext;
import javax.portlet.PortletRequest;
import javax.servlet.http.HttpServletRequest;
import java.util.Locale;
import java.util.Map;

public class JSFAuditSchemeHandler extends AuditSchemeHandler<FacesContext, FacesContext> {

    private static final Logger logger = LoggerFactory.getLogger(JSFAuditSchemeHandler.class);
    private static final String UNKNOWN_ADDRESS = "unknown address";
    private static final String UNKNOWN_HOST = "unknown host";

    public JSFAuditSchemeHandler(Map<String, String> parameters,
                                 StatefulScopes authenticationBindings) {
        super(parameters, authenticationBindings);
    }

    @Override
    protected String getRemoteAddress(Request<FacesContext> facesContextRequest) {
        String address = null;
        Object request = facesContextRequest.get().getExternalContext().getRequest();
        if (request instanceof HttpServletRequest) {
            ((HttpServletRequest) request).getRemoteAddr();
        } else {
            address = UNKNOWN_ADDRESS;
        }
        return address;
    }

    @Override
    protected String getRemoteHost(Request<FacesContext> facesContextRequest) {
        String host = null;
        Object request = facesContextRequest.get().getExternalContext().getRequest();
        if (request instanceof HttpServletRequest) {
            ((HttpServletRequest) request).getRemoteHost();
        } else {
            host = UNKNOWN_HOST;
        }
        return host;
    }

    @Override
    protected Locale getLocale(Request<FacesContext> facesContextRequest) {
        Locale locale = null;
        Object request = facesContextRequest.get().getExternalContext().getRequest();
        if (request instanceof HttpServletRequest) {
            locale = ((HttpServletRequest) request).getLocale();
        } else if (request instanceof PortletRequest) {
            locale = ((PortletRequest) request).getLocale();
        }
        if (locale == null) {
            locale = Locale.getDefault();
        }

        return locale;
    }
}
