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
 * display the jsp fragment if the Subject has got this Permission.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @since 1.0.0
 */
public class HasPermission extends ConditionalTagSupport {

    private static final long serialVersionUID = -2870113702917724315L;
    private final String defaultClassName = URLPermission.class.getName();
    private String className = defaultClassName;
    private String name = "";
    private String actions = "";
    private static final Logger logger = LoggerFactory.getLogger(HasPermission.class);
    private Injector injector;

    public HasPermission() {
        super();
    }

    protected boolean condition() throws JspTagException {

        try {
            String csName = (String) ExpressionEvaluatorManager.evaluate("className", this.className, String.class, this, pageContext);
            this.name = (String) ExpressionEvaluatorManager.evaluate("name", this.name, String.class, this, pageContext);
            this.actions = (String) ExpressionEvaluatorManager.evaluate("actions", this.actions, String.class, this, pageContext);
            if (csName != null && !csName.equals("")) {
                className = csName;
            }
        } catch (JspException e1) {
            throw new JspTagException(e1.getMessage());
        }


        Subject subject = TagUtils.getSubject(this.pageContext);
        if (subject == null) {
            return false;
        }


        Permission permission = null;
        try {
            Class clazz = Thread.currentThread().getContextClassLoader().loadClass(className);
            permission = net.sf.jguard.core.authorization.Permission.getPermission(clazz, name, actions);
        } catch (ClassNotFoundException e) {
            logger.warn("permission cannot be built ", e);
            throw new JspTagException(e.getMessage());
        }
        if (logger.isDebugEnabled()) {
            logger.debug("permission implementation class=" + permission);
            logger.debug("permission actions=" + actions);
        }
        if (injector == null) {
            injector = (Injector) pageContext.getSession().getServletContext().getAttribute(Injector.class.getName());
        }
        HttpAccessControllerUtils httpAccessControllerUtils = injector.getInstance(HttpAccessControllerUtils.class);
        return httpAccessControllerUtils.hasPermission((HttpServletRequest) pageContext.getRequest(), permission);

    }


    public String getActions() {
        return actions;
    }

    public void setActions(String actions) {
        this.actions = actions;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }


    public String getName() {
        return name;
    }


    public void setName(String name) {
        this.name = name;
    }

}
