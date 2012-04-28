package net.sf.jguard.jsf.authorization.filters;

import com.google.inject.Provider;
import net.sf.jguard.core.authorization.filters.AuthorizationFilter;
import net.sf.jguard.core.authorization.filters.PolicyDecisionPoint;
import net.sf.jguard.jsf.FacesContextAdapter;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

public class JSFAuthorizationFiltersProvider implements Provider<List<AuthorizationFilter<FacesContextAdapter, FacesContextAdapter>>> {

    private List<AuthorizationFilter<FacesContextAdapter, FacesContextAdapter>> authorizationFilters = new ArrayList<AuthorizationFilter<FacesContextAdapter, FacesContextAdapter>>();

    @Inject
    public JSFAuthorizationFiltersProvider(PolicyDecisionPoint<FacesContextAdapter, FacesContextAdapter> policyDecisionPoint) {
        authorizationFilters.add(policyDecisionPoint);
    }


    public List<AuthorizationFilter<FacesContextAdapter, FacesContextAdapter>> get() {
        return authorizationFilters;
    }
}
