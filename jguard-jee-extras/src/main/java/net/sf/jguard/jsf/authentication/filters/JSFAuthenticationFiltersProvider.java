package net.sf.jguard.jsf.authentication.filters;

import javax.inject.Inject;
import net.sf.jguard.core.authentication.filters.AuthenticationChallengeFilter;
import net.sf.jguard.core.authentication.filters.AuthenticationFiltersProvider;

import javax.faces.context.FacesContext;

public class JSFAuthenticationFiltersProvider extends AuthenticationFiltersProvider<FacesContext, FacesContext> {

    @Inject
    public JSFAuthenticationFiltersProvider(AuthenticationChallengeFilter<FacesContext, FacesContext> authenticationChallengeFilter) {
        super(authenticationChallengeFilter);
    }
}
