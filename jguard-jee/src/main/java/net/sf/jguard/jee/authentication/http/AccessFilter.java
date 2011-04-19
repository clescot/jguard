/*
	jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name$
http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles GAY

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


jGuard project home page:
http://sourceforge.net/projects/jguard/

*/

package net.sf.jguard.jee.authentication.http;

import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.Singleton;
import com.google.inject.TypeLiteral;
import net.sf.jguard.core.PolicyEnforcementPointOptions;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.enforcement.EntryPoint;
import net.sf.jguard.core.enforcement.PolicyEnforcementPoint;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.jee.provisioning.HttpServletProvisioningServicePoint;
import net.sf.jguard.jee.util.ContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.AccessControlException;
import java.security.Policy;

/**
 * Bound HTTP call to jGuard.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
@Singleton
public class AccessFilter implements Filter, EntryPoint {
    private static final Logger logger = LoggerFactory.getLogger(AccessFilter.class);


    private Injector injector;

    public AccessFilter() {
        super();

    }

    public void init(FilterConfig filterConfig) throws ServletException {

        injector = (Injector) filterConfig.getServletContext().getAttribute(Injector.class.getName());
        if (null == injector) {
            throw new IllegalArgumentException("Guice injector has not been properly initialized by ContextListener and put in the servlet context");
        }
        injector.injectMembers(this);

        logger.debug("server info = " + filterConfig.getServletContext().getServerInfo());
        logger.debug("servletContextName=" + filterConfig.getServletContext().getServletContextName());
        logger.debug("servlet Real Path=" + ContextUtil.getContextPath(filterConfig.getServletContext(), "/"));
        logger.debug("current Policy=" + Policy.getPolicy().getClass().getName());
        ServletContext context = filterConfig.getServletContext();


        //PROVISIONING init parameters
        String provisioningServicePointImpl = context.getInitParameter(PolicyEnforcementPointOptions.PROVISIONING_SERVICE_POINT.getLabel());
        if (provisioningServicePointImpl == null || provisioningServicePointImpl.equals("")) {
            logger.info(PolicyEnforcementPointOptions.PROVISIONING_SERVICE_POINT.getLabel() + " is null default settings is " + HttpServletProvisioningServicePoint.class.getName());
        }

        //PROPAGATE_THROWABLE
        boolean propagateThrowableOption = false;
        String propagateThrowable = context.getInitParameter(PolicyEnforcementPointOptions.PROPAGATE_THROWABLE.getLabel());
        if (propagateThrowable != null && !("").equals(propagateThrowable)) {
            propagateThrowableOption = Boolean.parseBoolean(propagateThrowable);
        } else {
            logger.info(PolicyEnforcementPointOptions.PROPAGATE_THROWABLE + " is not defined default setting " + propagateThrowableOption + " is set");
        }
        logger.info("propagateThrowable=" + propagateThrowable);


    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, final FilterChain filterChain) throws IOException, ServletException {
        AuthorizationBindings<HttpServletRequest, HttpServletResponse> authorizationBindings = null;
        Request<HttpServletRequest> request = null;
        Response<HttpServletResponse> response = null;
        try {
            PolicyEnforcementPoint<HttpServletRequest, HttpServletResponse> pep = injector.getInstance(Key.get(new TypeLiteral<PolicyEnforcementPoint<HttpServletRequest, HttpServletResponse>>() {
            }));
            request = injector.getInstance(Key.get(new TypeLiteral<Request<HttpServletRequest>>() {
            }));
            response = injector.getInstance(Key.get(new TypeLiteral<Response<HttpServletResponse>>() {
            }));
            authorizationBindings = injector.getInstance(Key.get(new TypeLiteral<AuthorizationBindings<HttpServletRequest, HttpServletResponse>>() {
            }));
            pep.doFilter(request, response);
        } catch (AccessControlException ace) {
            authorizationBindings.accessDenied(request, response);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            if (!servletResponse.isCommitted()) {
                ((HttpServletResponse) servletResponse).sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            } else {
                logger.error("reponse is already committed. we cannot send an 'internal server error' code (500) ");
            }
        }

    }

    public void destroy() {
    }

    public Injector getInjector() {
        return injector;
    }
}

