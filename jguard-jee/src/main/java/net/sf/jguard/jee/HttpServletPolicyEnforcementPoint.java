package net.sf.jguard.jee;

import com.google.inject.Inject;
import com.google.inject.servlet.RequestScoped;
import net.sf.jguard.core.authentication.Stateful;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.authorization.filters.AuthorizationFilter;
import net.sf.jguard.core.enforcement.PolicyEnforcementPoint;
import net.sf.jguard.core.lifecycle.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
@RequestScoped
public class HttpServletPolicyEnforcementPoint extends PolicyEnforcementPoint<HttpServletRequest, HttpServletResponse> {


    private static final Logger logger = LoggerFactory.getLogger(HttpServletPolicyEnforcementPoint.class.getName());

    @Inject
    public HttpServletPolicyEnforcementPoint(@Stateful List<AuthenticationFilter<HttpServletRequest, HttpServletResponse>> authenticationFilters,
                                             List<AuthorizationFilter<HttpServletRequest, HttpServletResponse>> authorizationFilters,
                                             boolean propagateThrowable) {
        super(authenticationFilters, authorizationFilters, propagateThrowable);
    }

    @Override
    protected void sendThrowable(Response<HttpServletResponse> response, Throwable throwable) {
        logger.error(throwable.getMessage(), throwable);
        HttpServletResponse res = response.get();
        try {
            res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (IOException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }
}
