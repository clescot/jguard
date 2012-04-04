/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name$
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
package net.sf.jguard.jee.taglib;

import net.sf.jguard.core.authentication.LoginContextWrapperImpl;
import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.http.HttpSession;
import javax.servlet.jsp.JspTagException;
import javax.servlet.jsp.PageContext;

public class TagUtils {

    private static final Logger logger = LoggerFactory.getLogger(TagUtils.class);

    /**
     * grab the Subject from the user's session and authenticate
     *
     * @param pageContext
     * @return subject
     * @throws JspTagException
     */
    protected static Subject getSubject(PageContext pageContext) throws JspTagException {
        Subject subject = null;
        HttpSession session = pageContext.getSession();
        if (session == null) {
            logger.warn("session is null");
            return subject;
        }
        LoginContextWrapperImpl httpUtils = (LoginContextWrapperImpl) session.getAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);

        if (httpUtils != null) {
            subject = httpUtils.getSubject();
        } else {
            logger.warn(" session does not contains an attribute keyed by " + StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
        }
        return subject;

    }

}
