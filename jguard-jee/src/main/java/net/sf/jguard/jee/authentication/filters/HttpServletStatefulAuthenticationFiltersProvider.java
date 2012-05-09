package net.sf.jguard.jee.authentication.filters;

import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.AsynchronousJGuardCallbackHandler;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.enforcement.GuestPolicyEnforcementPointFilter;
import net.sf.jguard.core.enforcement.StatefulAuthenticationFiltersProvider;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.inject.Inject;
import javax.servlet.http.HttpSession;
import java.util.List;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletStatefulAuthenticationFiltersProvider extends StatefulAuthenticationFiltersProvider<HttpServletRequestAdapter, HttpServletResponseAdapter> {

    @Inject
    public HttpServletStatefulAuthenticationFiltersProvider(AsynchronousJGuardCallbackHandler<HttpServletRequestAdapter, HttpServletResponseAdapter> jGuardCallbackHandler,
                                                            List<AuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>> authenticationFilters,
                                                            GuestPolicyEnforcementPointFilter<HttpServletRequestAdapter, HttpServletResponseAdapter> guestPolicyEnforcementPointFilter,
                                                            HttpServletRequestAdapter requestAdapter) {
        super(jGuardCallbackHandler,
                authenticationFilters,
                guestPolicyEnforcementPointFilter,
                new AuthenticationFilter<HttpServletRequestAdapter, HttpServletResponseAdapter>() {
                    public void doFilter(HttpServletRequestAdapter request, HttpServletResponseAdapter response, FilterChain<HttpServletRequestAdapter, HttpServletResponseAdapter> chain) {
                        LoginContextWrapper wrapper = (LoginContextWrapper) request.get().getSession(true).getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
                        if (null == wrapper || null == wrapper.getSubject()) {
                            throw new IllegalArgumentException("loginContext is null");
                        }
                        propagateWithSecurity(wrapper.getSubject(), request, response, chain);
                    }
                }, requestAdapter);
    }


    /**
     * @param request
     * @return true if a {@link LoginContextWrapper} is tied to the loginContextWrapper session attribute;
     *         false otherwise
     */
    @Override
    protected boolean alreadyAuthenticated(HttpServletRequestAdapter request) {
        HttpSession session = request.get().getSession(true);

        LoginContextWrapper wrapper = (LoginContextWrapper) session.getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
        return (null != wrapper);
    }

}
