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

package net.sf.jguard.core;

import javax.inject.Inject;
import com.google.inject.Injector;
import net.sf.jguard.core.authentication.AuthenticationStatus;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.callbackhandler.JGuardCallbackHandler;
import net.sf.jguard.core.filters.Filter;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.provisioning.ProvisioningServicePoint;
import net.sf.jguard.core.technology.ImpersonationScopes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.net.URL;
import java.security.Permission;


/**
 * {@link net.sf.jguard.core.filters.Filter} implementation dedicated to secure call in a safe way on multiple fields:
 * authentication of the call, authorization enforcement, check integrity and confidentiality.
 * this class must be a singleton.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public abstract class PolicyEnforcementPointFilter<Req, Res> implements Filter<Req, Res> {

    private ImpersonationScopes impersonationScopes;
    private ProvisioningServicePoint provisioningServicePoint = null;
    private static final Logger logger = LoggerFactory.getLogger(PolicyEnforcementPointFilter.class.getName());
    private boolean propagateThrowable;
    private StatefulAuthenticationServicePoint<Req, Res> authenticationServicePoint;
    private boolean redirectAfterAuthentication;
    @Inject
    private Injector injector;

    public PolicyEnforcementPointFilter(ImpersonationScopes impersonationScopes,
                                        StatefulAuthenticationServicePoint<Req, Res> authenticationServicePoint,
                                        boolean propagateThrowable,
                                        boolean redirectAfterAuthentication) {

        this.impersonationScopes = impersonationScopes;
        this.authenticationServicePoint = authenticationServicePoint;
        this.propagateThrowable = propagateThrowable;
        this.redirectAfterAuthentication = redirectAfterAuthentication;

        //initialize PolicyDecisionPoint


        //initialize Provisioning Service Point
        // String provisioningServicePointImpl = options.get(PolicyEnforcementPointOptions.PROVISIONING_SERVICE_POINT);
        // if (provisioningServicePointImpl == null || "".equals(provisioningServicePointImpl)) {
        //   logger.info("provisioningServicePoint is not set ");
        /* }else{
            this.provisioningServicePoint = initProvisioningServicePoint(provisioningServicePointImpl, filterConfigurationLocation);
            policyDecisionPoint.addAlwaysGrantedPermissionsToPolicy(provisioningServicePoint.getGrantedPermissions());
        */
        //}


        //include permissions granted by some AuthenticationSchemeHandler registered in AuthenticationServicePoint.


    }


    public ProvisioningServicePoint getProvisioningServicePoint() {
        return provisioningServicePoint;
    }


    private ProvisioningServicePoint initProvisioningServicePoint(String provisioningServicePointImpl, URL filterConfigurationLocation) {
        logger.debug("initializing ProvisioningServicePoint");
        logger.debug("provisioningServicePointImpl=" + provisioningServicePointImpl);
        ProvisioningServicePoint psp;
        try {
            psp = (ProvisioningServicePoint) Thread.currentThread().getContextClassLoader().loadClass(provisioningServicePointImpl).newInstance();
            psp.init(filterConfigurationLocation);
        } catch (InstantiationException iex) {
            logger.error(iex.getMessage(), iex);
            throw new IllegalArgumentException(iex);
        } catch (ClassNotFoundException cne) {
            logger.error(cne.getMessage(), cne);
            throw new IllegalArgumentException(cne);
        } catch (IllegalAccessException iae) {
            logger.error(iae.getMessage(), iae);
            throw new IllegalArgumentException(iae);
        }

        return psp;
    }


    /**
     * authenticate client request after registering it.
     *
     * @return <code>true</code> if authentication succeeds, <code>false</code> otherwise
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *          when authentication fails
     */
    private AuthenticationStatus authenticateAfterRegistration(Request request, Response response, JGuardCallbackHandler callbackHandler) {
        //authenticationBindings.setRequestAttribute(CoreConstants.REGISTRATION_DONE, Boolean.TRUE);

        return authenticationServicePoint.authenticate(request, response, callbackHandler).getStatus();

    }



    


}
