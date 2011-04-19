package net.sf.jguard.core.authentication.filters;

import com.google.inject.Provider;

import java.util.ArrayList;
import java.util.List;

/**
 * return the {@link AuthenticationFilter} which process a regular authentication (i.e non-guest).
 *
 * @param <Req>
 * @param <Res>
 */
public abstract class AuthenticationFiltersProvider<Req, Res> implements Provider<List<AuthenticationFilter<Req, Res>>> {
    private List<AuthenticationFilter<Req, Res>> authenticationFilters = new ArrayList<AuthenticationFilter<Req, Res>>();

    public AuthenticationFiltersProvider(AuthenticationChallengeFilter<Req, Res> authenticationChallengeFilter) {
        authenticationFilters.add(authenticationChallengeFilter);
    }

    public List<AuthenticationFilter<Req, Res>> get() {
        return authenticationFilters;
    }
}
