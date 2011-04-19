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
package net.sf.jguard.jsf;

import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import net.sf.jguard.core.PolicyEnforcementPointOptions;
import net.sf.jguard.core.authentication.AuthenticationScope;
import net.sf.jguard.core.authentication.configuration.JGuardAuthenticationMarkups;
import net.sf.jguard.core.authorization.AuthorizationBindings;
import net.sf.jguard.core.enforcement.EntryPoint;
import net.sf.jguard.core.enforcement.PolicyEnforcementPoint;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.faces.context.FacesContext;
import javax.faces.event.PhaseEvent;
import javax.faces.event.PhaseId;
import javax.faces.event.PhaseListener;
import javax.portlet.PortletContext;
import javax.portlet.PortletRequest;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.AccessControlException;
import java.util.Map;


/**
 * JSF PhaseListener implementation to control in one unique point all access.
 * this class do a bridge between JSF and jGuard and its PolicyEnforcementPoint.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class AccessListener implements PhaseListener, EntryPoint {

    private static final long serialVersionUID = 2813722561916091752L;
    private boolean initialized;
    public static final String LISTENER_CONFIGURATION_LOCATION = "listenerConfigurationLocation";

    private static final Logger logger = LoggerFactory.getLogger(AccessListener.class.getName());
    private PolicyEnforcementPoint policyEnforcementPoint;
    private Injector injector;

    public void afterPhase(PhaseEvent event) {
        logger.debug(" after phase " + event.getPhaseId());
        if (PhaseId.RESTORE_VIEW.equals(event.getPhaseId()) ||
                PhaseId.INVOKE_APPLICATION.equals(event.getPhaseId())) {
            try {
                PolicyEnforcementPoint<FacesContext, FacesContext> pep = injector.getInstance(Key.get(new TypeLiteral<PolicyEnforcementPoint<FacesContext, FacesContext>>() {
                }));
                Request<FacesContext> request = injector.getInstance(Key.get(new TypeLiteral<Request<FacesContext>>() {
                }));
                Response<FacesContext> response = injector.getInstance(Key.get(new TypeLiteral<Response<FacesContext>>() {
                }));
                AuthorizationBindings<FacesContext, FacesContext> authorizationBindings = injector.getInstance(Key.get(new TypeLiteral<AuthorizationBindings<FacesContext, FacesContext>>() {
                }));
                try {
                    pep.doFilter(request, response);
                } catch (AccessControlException ace) {
                    authorizationBindings.accessDenied(request, response);
                }
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
        }
    }

    public void beforePhase(PhaseEvent event) {
        logger.debug(" before phase " + event.getPhaseId());
        if (!initialized) {
            initialize(event);
            initialized = true;
        }
    }

    private void initialize(PhaseEvent event) {
        FacesContext fc = event.getFacesContext();
        injector = (Injector) fc.getExternalContext().getApplicationMap().get(Injector.class.getName());
        if (injector == null) {
            throw new IllegalArgumentException("no Guice injector instance has been bound to " + Injector.class.getName() + " key in the application context scope");
        }
        policyEnforcementPoint = injector.getInstance(Key.get(new TypeLiteral<PolicyEnforcementPoint<FacesContext, FacesContext>>() {
        }));
        //init parameter is now in the context
        String filterConfigurationLocation = ExternalContextUtil.getContextPath(fc.getExternalContext(), fc.getExternalContext().getInitParameter(LISTENER_CONFIGURATION_LOCATION));
        URL filterconfigurationlocationUrl;
        try {
            filterconfigurationlocationUrl = new URL(filterConfigurationLocation);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        String scope = fc.getExternalContext().getInitParameter(JGuardAuthenticationMarkups.SCOPE.getLabel());
        AuthenticationScope authenticationScope = null;
        if (scope != null) {
            authenticationScope = AuthenticationScope.valueOf(scope);
        }
        if (authenticationScope == null) {
            authenticationScope = AuthenticationScope.LOCAL;
        }


        String applicationName = fc.getExternalContext().getInitParameter(PolicyEnforcementPointOptions.APPLICATION_NAME.getLabel());
        Injector initialInjector;
        Object request = fc.getExternalContext().getRequest();
        if (applicationName == null || "".equals(applicationName)) {
            applicationName = getApplicationNameFromContext(request);
        }

        initialInjector = getInitialInjector(fc.getExternalContext().getApplicationMap());


        boolean propagateThrowableOption = false;
        String propagateThrowable = fc.getExternalContext().getInitParameter(PolicyEnforcementPointOptions.PROPAGATE_THROWABLE.getLabel());
        if (propagateThrowable != null && !propagateThrowable.isEmpty()) {
            propagateThrowableOption = Boolean.parseBoolean(propagateThrowable);
        }

    }

    private Injector getInitialInjector(Map applicationAttributes) {
        Injector initialInjector;
        initialInjector = (Injector) applicationAttributes.get(Injector.class.getName());
        if (initialInjector == null) {
            throw new IllegalStateException("no Injector is bound to the " + Injector.class.getName() + " variable in the servletContext");
        }
        return initialInjector;
    }

    private String getApplicationNameFromContext(Object request) {
        String applicationName;
        if (HttpServletRequest.class.isAssignableFrom(request.getClass())) {
            ServletContext servletContext = ((HttpServletRequest) request).getSession(true).getServletContext();
            applicationName = servletContext.getServletContextName();
        } else if (PortletRequest.class.isAssignableFrom(request.getClass())) {
            PortletContext portletContext = ((PortletRequest) request).getPortletSession(true).getPortletContext();
            applicationName = portletContext.getPortletContextName();
        } else {
            throw new IllegalArgumentException("request with class" + request.getClass().getName() + " is not handled");
        }

        return applicationName;
    }


    /**
     * we can select only one phase or all phases
     * and we want to be called after  the RESTORE_VIEW
     * and the INVOKE_APPLICATION phases.
     * so we return ANY_PHASE and the selection will be done
     * in the afterPhase method.
     *
     * @ return PhaseId.ANY_PHASE
     */
    public PhaseId getPhaseId() {
        return PhaseId.ANY_PHASE;
    }

    public Injector getInjector() {
        return injector;
    }
}
