package net.sf.jguard.jsf.authorization.filters;

import javax.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.authorization.filters.AuthorizationFilter;
import net.sf.jguard.core.authorization.filters.PolicyDecisionPoint;

import javax.faces.context.FacesContext;
import java.util.ArrayList;
import java.util.List;

public class JSFAuthorizationFiltersProvider implements Provider<List<AuthorizationFilter<FacesContext, FacesContext>>> {

    private List<AuthorizationFilter<FacesContext, FacesContext>> authorizationFilters = new ArrayList<AuthorizationFilter<FacesContext, FacesContext>>();

    @Inject
    public JSFAuthorizationFiltersProvider(PolicyDecisionPoint<FacesContext, FacesContext> policyDecisionPoint) {
        authorizationFilters.add(policyDecisionPoint);
    }


    public List<AuthorizationFilter<FacesContext, FacesContext>> get() {
        return authorizationFilters;
    }
}
