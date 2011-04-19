package net.sf.jguard.jsf;

import net.sf.jguard.core.lifecycle.Request;

import javax.faces.context.FacesContext;


public class JSFRequestAdapter implements Request<FacesContext> {
    public FacesContext get() {
        return FacesContext.getCurrentInstance();
    }
}
