package net.sf.jguard.jsf;

import net.sf.jguard.core.lifecycle.Response;

import javax.faces.context.FacesContext;

public class JSFResponseAdapter implements Response<FacesContext> {
    public FacesContext get() {
        return FacesContext.getCurrentInstance();
    }
}
