package net.sf.jguard.jsf.authentication.callbacks;

import net.sf.jguard.jee.authentication.schemes.AuditSchemeHandler;
import net.sf.jguard.jsf.FacesContextAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.portlet.PortletRequest;
import javax.servlet.http.HttpServletRequest;
import java.util.Locale;
import java.util.Map;

public class JSFAuditSchemeHandler extends AuditSchemeHandler<FacesContextAdapter, FacesContextAdapter> {

    private static final Logger logger = LoggerFactory.getLogger(JSFAuditSchemeHandler.class);
    private static final String UNKNOWN_ADDRESS = "unknown address";
    private static final String UNKNOWN_HOST = "unknown host";

    public JSFAuditSchemeHandler(Map<String, String> parameters) {
        super(parameters);
    }

    @Override
    protected String getRemoteAddress(FacesContextAdapter facesContextRequest) {
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
    protected String getRemoteHost(FacesContextAdapter facesContextRequest) {
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
    protected Locale getLocale(FacesContextAdapter facesContextRequest) {
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
