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


import com.google.inject.Injector;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.jee.authorization.HttpAccessControllerUtils;
import org.apache.taglibs.standard.lang.support.ExpressionEvaluatorManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspTagException;
import javax.servlet.jsp.jstl.core.ConditionalTagSupport;
import java.security.Permission;


/**
 * display the jsp fragment if the user has got the right to access to the ressource
 * protected by the permission.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net ">Charles Lescot</a>
 */
public class Authorized extends ConditionalTagSupport {
    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(Authorized.class);

    /**
     * serial version id.
     */
    private static final long serialVersionUID = 3833742183621736755L;
    private String uri;
    private String permission = URLPermission.class.getName();
    private Injector injector;
    private static final String PERMISSION = "permission";
    private static final String URI = "uri";
    private static final String DUMMY_NAME = "dummy name";

    public Authorized() {
        super();

    }


    /**
     * @return uri
     */
    public String getUri() {
        return uri;
    }


    /**
     * @param strUri
     */
    public void setUri(String strUri) {
        uri = strUri;

    }


    /**
     * allow or not to display jsp content;depends on access rights.
     *
     * @return true if tag displays content when user is authorized; false otherwise
     * @see javax.servlet.jsp.jstl.core.ConditionalTagSupport#condition()
     */
    protected boolean condition() throws JspTagException {

        try {
            this.uri = (String) ExpressionEvaluatorManager.evaluate(URI, this.uri, String.class, this, pageContext);
            String perm = (String) ExpressionEvaluatorManager.evaluate(PERMISSION, this.permission, String.class, this, pageContext);
            if (perm != null && !perm.equals("")) {
                permission = perm;
            }
        } catch (JspException e1) {
            logger.error("condition()", e1);
            throw new JspTagException(e1.getMessage());
        }

        if (logger.isDebugEnabled()) {
            logger.debug("<jguard:authorized> tag uri=" + uri);
        }

        Subject subject = TagUtils.getSubject(this.pageContext);
        if (subject == null) {
            return false;
        }

        StringBuffer actions = new StringBuffer();
        actions.append(uri);

        Permission urlPermission = null;
        try {
            urlPermission = net.sf.jguard.core.authorization.permissions.Permission.getPermission(URLPermission.class, DUMMY_NAME, actions.toString());
        } catch (ClassNotFoundException e) {
            logger.warn("permission cannot be built ", e);
        }
        if (logger.isDebugEnabled()) {
            logger.debug("permission implementation class=" + permission);
            logger.debug("permission actions=" + actions.toString());
            logger.debug("URLPermission=" + urlPermission);
        }
        if (injector == null) {
            injector = (Injector) pageContext.getSession().getServletContext().getAttribute(Injector.class.getName());
        }
        HttpAccessControllerUtils httpAccessControllerUtils = injector.getInstance(HttpAccessControllerUtils.class);
        return httpAccessControllerUtils.hasPermission((HttpServletRequest) pageContext.getRequest(), urlPermission);

    }


    public String getPermission() {
        return permission;
    }


    public void setPermission(String permission) {
        this.permission = permission;
    }
}
