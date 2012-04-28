package net.sf.jguard.core.authentication.filters;

import com.google.inject.Provider;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import java.util.ArrayList;
import java.util.List;

/**
 * return the {@link AuthenticationFilter} which process a regular authentication (i.e non-guest).
 *
 * @param <Req>
 * @param <Res>
 */
public abstract class AuthenticationFiltersProvider<Req extends Request, Res extends Response> implements Provider<List<AuthenticationFilter<Req, Res>>> {
    private List<AuthenticationFilter<Req, Res>> authenticationFilters = new ArrayList<AuthenticationFilter<Req, Res>>();

    public AuthenticationFiltersProvider(AuthenticationChallengeFilter<Req, Res> authenticationChallengeFilter) {
        authenticationFilters.add(authenticationChallengeFilter);
    }

    public List<AuthenticationFilter<Req, Res>> get() {
        return authenticationFilters;
    }
}
