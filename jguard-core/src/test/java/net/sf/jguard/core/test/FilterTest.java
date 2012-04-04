package net.sf.jguard.core.test;

import com.google.inject.Module;
import com.mycila.testing.plugin.guice.ModuleProvider;
import net.sf.jguard.core.authentication.AuthenticationScope;
import net.sf.jguard.core.authentication.MockAuthenticationServicePoint;
import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import net.sf.jguard.core.authentication.manager.MockAuthenticationManagerModule;
import net.sf.jguard.core.authentication.schemes.DummyAuthenticationSchemeHandler;
import net.sf.jguard.core.authorization.MockAuthorizationBindings;
import net.sf.jguard.core.authorization.manager.MockAuthorizationManager;
import net.sf.jguard.core.enforcement.MockPolicyEnforcementPoint;
import net.sf.jguard.core.filters.Filter;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.inject.Inject;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/**
 * base test class dedicated to test {@link net.sf.jguard.core.filters.Filter} implementations.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class FilterTest extends JGuardTest {
    @Inject
    protected MockAuthenticationServicePoint authenticationServicePoint;
    @Inject
    protected Request<MockRequest> request;
    @Inject
    protected Response<MockResponse> response;
    @Inject
    protected MockAuthorizationBindings authorizationBindings;


    @Inject
    protected DummyAuthenticationSchemeHandler<MockRequest, MockResponse> schemeHandler;
    @Inject
    protected MockPolicyEnforcementPoint policyEnforcementPoint;
    protected Filter<MockRequest, MockResponse> beforeFilter;
    protected Filter<MockRequest, MockResponse> afterFilter;

    public void setUp(Filter<MockRequest, MockResponse> filter) {
        final List<Filter<MockRequest, MockResponse>> filters = new ArrayList<Filter<MockRequest, MockResponse>>();
        beforeFilter = mock(Filter.class);
        filterDoFilter(beforeFilter);

        afterFilter = mock(Filter.class);
        filterDoFilter(afterFilter);

        filters.add(beforeFilter);
        filters.add(filter);
        filters.add(afterFilter);
        policyEnforcementPoint.setFilters(filters);
    }


    /**
     * provides a MockAuthenticationManagerModule, which provides a MockAuthenticationManager.
     *
     * @return
     */
    @Override
    protected AuthenticationManagerModule buildAuthenticationManagerModule() {
        URL url = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_AUTHENTICATION_XML.getLabel());
        if (url == null) {
            throw new IllegalStateException(JGuardTestFiles.J_GUARD_AUTHENTICATION_XML.getLabel() + " must be present in the classpath");
        }
        return new MockAuthenticationManagerModule(JGuardTestFiles.JGUARD_STRUTS_EXAMPLE.getLabel(), url);
    }

    @ModuleProvider
    public Iterable<Module> providesModules() {
        URL url = Thread.currentThread().getContextClassLoader().getResource(".");
        List<Module> modules = super.providesModules(AuthenticationScope.LOCAL, true,
                url,
                MockAuthorizationManager.class);
        modules.add(new MockModule());
        return modules;
    }

    /**
     * permit to simulate for the mockedFilter, a call to the chainFilter.doFilter method.
     *
     * @param mockedFilter
     */
    private void filterDoFilter(Filter mockedFilter) {
        doAnswer(new Answer() {
            public Object answer(InvocationOnMock invocation) {
                Object[] args = invocation.getArguments();
                ((FilterChain) args[2]).doFilter((Request) args[0], (Response) args[1]);
                return null;
            }
        })
                .when(mockedFilter).doFilter(any(Request.class), any(Response.class), any(FilterChain.class));
    }
}
