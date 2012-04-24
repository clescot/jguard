/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.

http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles Lescot

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
package net.sf.jguard.jee.listeners;

import net.sf.jguard.core.authentication.LoginContextWrapperImpl;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.authentication.manager.JGuardAuthenticationManagerMarkups;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.http.HttpSessionAttributeListener;
import javax.servlet.http.HttpSessionBindingEvent;

/**
 * Audit JGuard Subject of http sessions, generating log for Subject changes
 *
 * @author Frederico Borelli
 * @see net.sf.jguard.core.audit.AuditManager
 */
public class SessionAttributeListener implements HttpSessionAttributeListener {

    static public final Logger logger = LoggerFactory.getLogger(SessionAttributeListener.class);

    public void attributeAdded(HttpSessionBindingEvent event) {
        if (event.getName().equals(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER)) {
            JGuardCredential identity;
            try {
                identity = getIdentityCredential(event);
                logger.info("subject with identityCredential=" + identity + " is created ");
            } catch (AuthenticationException ex) {
                logger.warn(ex.getMessage());
            }

        }
    }

    private JGuardCredential getIdentityCredential(final HttpSessionBindingEvent event) throws AuthenticationException {
        Subject subject = ((LoginContextWrapperImpl) event.getValue()).getSubject();
        AuthenticationManager authenticationManager = (AuthenticationManager) event.getSession().getServletContext().getAttribute(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel());
        return authenticationManager.getIdentityCredential(subject);
    }

    public void attributeRemoved(HttpSessionBindingEvent event) {
        if (event.getName().equals(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER)) {
            JGuardCredential identity;
            try {
                identity = getIdentityCredential(event);
                logger.info("subject with identityCredential=" + identity + " is removed ");
            } catch (AuthenticationException ex) {
                logger.warn(ex.getMessage());
            }

        }
    }

    public void attributeReplaced(HttpSessionBindingEvent event) {
        if (event.getName().equals(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER)) {
            JGuardCredential identity;
            try {
                identity = getIdentityCredential(event);
                logger.info("subject with identityCredential=" + identity + " is replaced ");
            } catch (AuthenticationException ex) {
                logger.warn(ex.getMessage());
            }

        }
    }

}
