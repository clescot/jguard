package net.sf.jguard.core.authentication.filters;

import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;

import javax.inject.Inject;

public class MockAuthenticationFiltersProvider extends AuthenticationFiltersProvider<MockRequestAdapter, MockResponseAdapter> {
    @Inject
    public MockAuthenticationFiltersProvider(AuthenticationChallengeFilter<MockRequestAdapter, MockResponseAdapter> mockRequestMockResponseAuthenticationChallengeFilter) {
        super(mockRequestMockResponseAuthenticationChallengeFilter);
    }
}
