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
package net.sf.jguard.core.enforcement;

import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.authorization.filters.AuthorizationFilter;
import net.sf.jguard.core.filters.Filter;
import net.sf.jguard.core.filters.FilterChain;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.List;


/**
 * Policy Enforcement Point.
 * main generic(i.e not technological-bound) entry point to jguard.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @since 2.0
 */
public abstract class PolicyEnforcementPoint<Req, Res> implements FilterChain<Req, Res>, Cloneable {

    private static final Logger logger = LoggerFactory.getLogger(PolicyEnforcementPoint.class.getName());
    private static final int DEFAULT_CAPACITY = 50;
    private static final String FILTER_SEPARATOR = ",";

    protected List<Filter<Req, Res>> filters = new ArrayList<Filter<Req, Res>>();
    private boolean propagateThrowable;
    private int counter = 0;


    /**
     * @param authenticationFilters
     * @param authorizationFilters
     * @param propagateThrowable
     */
    public PolicyEnforcementPoint(List<AuthenticationFilter<Req, Res>> authenticationFilters,
                                  List<AuthorizationFilter<Req, Res>> authorizationFilters,
                                  boolean propagateThrowable) {
        this.filters.addAll(authenticationFilters);
        this.filters.addAll(authorizationFilters);
        this.propagateThrowable = propagateThrowable;
        if (logger.isDebugEnabled()) {
            logger.debug("propagateThrowable=" + propagateThrowable);
            StringBuilder output = new StringBuilder(DEFAULT_CAPACITY);
            output.append("PEP structure:\n");
            output.append(authenticationFilters.size());
            output.append(" authenticationFilters[");

            for (AuthenticationFilter authenticationFilter : authenticationFilters) {
                output.append(authenticationFilter.getClass().getSimpleName() + FILTER_SEPARATOR);
            }

            if (!authenticationFilters.isEmpty()) {
                output.deleteCharAt(output.lastIndexOf(FILTER_SEPARATOR));
            } else {
                throw new IllegalStateException("authenticationFilters list is empty");
            }
            output.append("]\n");
            output.append(authorizationFilters.size() + " authorizationFilters[");
            for (AuthorizationFilter authorizationFilter : authorizationFilters) {
                output.append(authorizationFilter.getClass().getSimpleName() + FILTER_SEPARATOR);
            }
            if (!authorizationFilters.isEmpty()) {
                output.deleteCharAt(output.lastIndexOf(FILTER_SEPARATOR));
            } else {
                throw new IllegalStateException("authorizationFilters list is empty");
            }
            output.append("]");
            logger.debug(output.toString());
        }
    }

    public void doFilter(Request<Req> request,
                         Response<Res> response) {

        try {
            doInternalFilter(request, response);
        } catch (AccessControlException ace) {
            throw ace;
        } catch (Throwable throwable) {
            logger.error(throwable.getMessage());
            //for debug purpose, we throw the exception
            //MUST only used in DEVELOPMENT phase
            //NEVER in PRODUCTION phase
            if (propagateThrowable) {
                throw new IllegalStateException(throwable);
            } else {
                sendThrowable(response, throwable);
            }
        }
    }

    /**
     * propagate a Throwable instance to the client according to the underlying protocol.
     *
     * @param response
     * @param throwable
     */
    protected abstract void sendThrowable(Response<Res> response, Throwable throwable);


    /**
     * doFilter request and response in a filterChain.
     * it is an implementation of the 'chain of responsability' design pattern.
     *
     * @param request
     * @param response
     */
    public void doInternalFilter(Request<Req> request,
                                 Response<Res> response) {
        int filterSize = getFilters().size();
        if (counter < filterSize) {
            Filter<Req, Res> filter = getFilters().get(counter);
            counter++;
            if (logger.isDebugEnabled()) {
                logger.debug(" in FilterChain : before filter " + filter.getClass().getSimpleName());
            }
            filter.doFilter(request, response, this);
            if (logger.isDebugEnabled()) {
                logger.debug(" in FilterChain : after filter " + filter.getClass().getSimpleName());
            }
        } else if (counter > filterSize) {
            //we try to reach a filter but the tail of the filterChain has been reached
            throw new IllegalStateException(" we cannot handle this doFilter call because all filters has already been called once ");
        } else {
            counter++;
        }

        //if (counter == filter size): the last filter has been reached, so we stop to call the filter chain
    }


    @Override
    public Object clone() throws CloneNotSupportedException {
        PolicyEnforcementPoint clone = (PolicyEnforcementPoint) super.clone();
        clone.filters = getFilters();
        return clone;

    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (Filter filter : getFilters()) {
            sb.append(filter.toString());
        }
        return sb.toString();
    }

    public List<Filter<Req, Res>> getFilters() {
        return filters;
    }
}
