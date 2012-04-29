package net.sf.jguard.jsf;

import com.google.inject.servlet.RequestScoped;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.lifecycle.StatefulRequest;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.portlet.PortletRequest;
import javax.portlet.PortletSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Iterator;

@RequestScoped
public class FacesContextAdapter implements StatefulRequest<FacesContext>, Response<FacesContext> {

    private FacesContext facesContext;

    @Inject
    public FacesContextAdapter(FacesContext facesContext) {
        this.facesContext = facesContext;
    }

    public FacesContext get() {
        return facesContext;
    }


    private ExternalContext getExternalContext() {
        return FacesContext.getCurrentInstance().getExternalContext();
    }

    public void setRequestAttribute(String key, Object value) {
        getExternalContext().getRequestMap().put(key, value);
    }


    public Object getRequestAttribute(String key) {
        return getExternalContext().getRequestMap().get(key);
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
