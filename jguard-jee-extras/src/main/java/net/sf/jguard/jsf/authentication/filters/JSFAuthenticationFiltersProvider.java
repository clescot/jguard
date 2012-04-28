package net.sf.jguard.jsf.authentication.filters;

import net.sf.jguard.core.authentication.filters.AuthenticationChallengeFilter;
import net.sf.jguard.core.authentication.filters.AuthenticationFiltersProvider;
import net.sf.jguard.jsf.FacesContextAdapter;

import javax.inject.Inject;

public class JSFAuthenticationFiltersProvider extends AuthenticationFiltersProvider<FacesContextAdapter, FacesContextAdapter> {

    @Inject
    public JSFAuthenticationFiltersProvider(AuthenticationChallengeFilter<FacesContextAdapter, FacesContextAdapter> authenticationChallengeFilter) {
        super(authenticationChallengeFilter);
    }
}
