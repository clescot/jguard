package net.sf.jguard.jee.authentication.filters;

import net.sf.jguard.core.authentication.AuthenticationServicePoint;
import net.sf.jguard.core.authentication.LoginContextWrapper;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.enforcement.GuestPolicyEnforcementPointFilter;
import net.sf.jguard.core.enforcement.StatefulAuthenticationFiltersProvider;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.List;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletStatefulAuthenticationFiltersProvider extends StatefulAuthenticationFiltersProvider<HttpServletRequest, HttpServletResponse> {

    @Inject
    public HttpServletStatefulAuthenticationFiltersProvider(Request<HttpServletRequest> request,
                                                            Response<HttpServletResponse> response,
                                                            AuthenticationServicePoint<HttpServletRequest, HttpServletResponse> authenticationServicePoint,
                                                            List<AuthenticationFilter<HttpServletRequest, HttpServletResponse>> authenticationFilters,
                                                            GuestPolicyEnforcementPointFilter<HttpServletRequest, HttpServletResponse> guestPolicyEnforcementPointFilter) {
        super(request,
                response,
                authenticationServicePoint,
                authenticationFilters,
                guestPolicyEnforcementPointFilter,
                new AuthenticationFilter<HttpServletRequest, HttpServletResponse>() {
                    public void doFilter(Request<HttpServletRequest> request, Response<HttpServletResponse> response, FilterChain<HttpServletRequest, HttpServletResponse> chain) {
                        LoginContextWrapper wrapper = (LoginContextWrapper) request.get().getSession(true).getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
                        if (null == wrapper || null == wrapper.getSubject()) {
                            throw new IllegalArgumentException("loginContext is null");
                        }
                        propagateWithSecurity(wrapper.getSubject(), request, response, chain);
                    }
                });
    }


    /**
     * @param request
     * @return true if a {@link LoginContextWrapper} is tied to the loginContextWrapper session attribute;
     *         false otherwise
     */
    @Override
    protected boolean alreadyAuthenticated(Request<HttpServletRequest> request) {
        HttpSession session = request.get().getSession(true);

        LoginContextWrapper wrapper = (LoginContextWrapper) session.getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
        return (null != wrapper);
    }

}
