package net.sf.jguard.jsf;

import com.google.inject.servlet.RequestScoped;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.faces.context.FacesContext;
import javax.inject.Inject;

@RequestScoped
public class FacesContextAdapter implements Request<FacesContext>, Response<FacesContext> {

    private FacesContext facesContext;

    @Inject
    public FacesContextAdapter(FacesContext facesContext) {
        this.facesContext = facesContext;
    }

    public FacesContext get() {
        return facesContext;
    }
}
