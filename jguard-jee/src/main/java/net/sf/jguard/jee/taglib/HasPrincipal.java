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
import com.google.inject.Key;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authorization.permissions.PrincipalUtils;
import net.sf.jguard.core.authorization.permissions.RolePrincipal;
import org.apache.taglibs.standard.lang.support.ExpressionEvaluatorManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspTagException;
import javax.servlet.jsp.jstl.core.ConditionalTagSupport;
import java.security.Principal;
import java.util.*;


/**
 * display the jsp fragment if the Subject has got this Principal/role.
 * principals are divided by ';' character, which are divided with ',' to include
 * multiple strings to build the principal.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HasPrincipal extends ConditionalTagSupport {

    /**
     * Logger for this class
     */
    private static final Logger logger = LoggerFactory.getLogger(HasPrincipal.class);
    /**
     * serial version id.
     */
    private static final long serialVersionUID = 3257284721280235318L;
    private String principals;
    private List principalsList;
    private static final String ALL = "ALL";
    private static final String ANY = "ANY";
    private static final String NONE = "NONE";

    //default setting is ANY
    private String operator = ANY;
    private Class defaultClassName = RolePrincipal.class;
    private Class clazz = defaultClassName;
    private Class[] defaultParameterTypes = new Class[]{String.class, String.class};
    private Class[] parameterTypes = defaultParameterTypes;
    private String applicationName;


    /**
     * @param strUri
     */
    public void setPrincipals(String strUri) {
        principals = strUri;
        principalsList = Arrays.asList(principals.split(","));
    }


    /**
     * allow or not to display jsp content;depends on user's principalsArray (Principals).
     *
     * @return true if tag displays content when user has got the specified role(principal); false otherwise
     * @see javax.servlet.jsp.jstl.core.ConditionalTagSupport#condition()
     */
    protected boolean condition() throws JspTagException {

        try {
            this.principals = (String) ExpressionEvaluatorManager.evaluate("principalsArray", this.principals, String.class, this, pageContext);
            principalsList = Arrays.asList(principals.split(","));
        } catch (JspException e1) {
            logger.error("condition()", e1);
            throw new JspTagException(e1.getMessage());
        }
        if (logger.isDebugEnabled()) {
            logger.debug("<jguard:authorized> tag uri=" + principals);
            logger.debug("<jguard:authorized> tag operator=" + operator);
        }

        Subject subject = TagUtils.getSubject(this.pageContext);
        if (subject == null) {
            return false;
        }

        Set principalsFromSubject = subject.getPrincipals();
        if (applicationName == null) {
            Injector injector = (Injector) pageContext.getServletContext().getAttribute(Injector.class.getName());
            applicationName = injector.getInstance(Key.get(String.class, ApplicationName.class));
        }

        for (int j = 0; j < principalsList.size(); j++) {
            Principal ppal = null;
            String principalString = (String) principalsList.get(j);

            ppal = getPrincipal(clazz, this.parameterTypes, principalString, applicationName);

            if (ppal == null) {
                logger.warn(" wrong arguments in the HasPrincipal tag \n class=" + clazz.getName() + "\n parameterTypes=" + Arrays.toString(parameterTypes) + "\n principalsArray=" + principalsList);
                return false;
            }

            if (!principalsFromSubject.contains(ppal) && ALL.equals(operator)) {
                return false;
            } else {
                boolean active = isActive(ppal, principalsFromSubject);

                //principals contains  principalString
                if (operator.equals(ANY) && active) {
                    return true;
                } else if (operator.equals(NONE) && active) {
                    return false;
                }
            }
        }

        //each item has been successfully checked so 
        //the global collection asnwer to the ALL or NONE 
        // requirement
        if (operator.equals(ALL) || operator.equals(NONE)) {
            return true;
            // no item asnwer to the ANY requirement
            // the check fails
        } else if (operator.equals(ANY)) {
            return false;
        }

        return false;

    }


    /**
     * @return Returns the principals.
     */
    public String getPrincipals() {
        return principals;
    }

    /**
     * @return Returns the operator.
     */
    public String getOperator() {
        return operator;
    }

    /**
     * @param operator The operator to set.
     */
    public void setOperator(String operator) {
        String upper = operator.toUpperCase();
        if (upper.equals(ALL) || upper.equals(ANY) || upper.equals(NONE)) {
            this.operator = upper;
        }
    }


    public final Class getClazz() {
        return clazz;
    }


    public final void setClassName(String className) {
        try {
            this.clazz = Class.forName(className);
        } catch (ClassNotFoundException e) {
            logger.info(" 'className' attribute does not map to an existing or reachable class ");
        }
    }


    public final Class[] getParameterTypes() {
        return parameterTypes.clone();
    }


    public String getApplicationName() {
        return applicationName;
    }


    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    private static Principal getPrincipal(Class clazz, Class[] parameterTypes, String principalName, String applicationName) {
        Principal ppal;
        if (clazz.getName().equals(RolePrincipal.class.getName())) {
            List args = new ArrayList();
            args.add(principalName);
            args.add(applicationName);
            ppal = PrincipalUtils.getPrincipal(clazz, parameterTypes, args.toArray());
        } else {
            ppal = PrincipalUtils.getPrincipal(clazz, parameterTypes, new Object[]{(principalName).split(";")});
        }

        return ppal;
    }

    /**
     * we check the active status of the principal against
     * the set of principals.
     * if the principa
     *
     * @param ppal       to check
     * @param principals reference
     * @return <strong>true</strong> if principal is active or is not a RolePrincipal instance,
     *         <strong>false</strong> otherwise
     */
    private boolean isActive(Principal ppal, Set principals) {
        RolePrincipal rolePrincipal = null;
        if (ppal instanceof RolePrincipal) {
            rolePrincipal = (RolePrincipal) ppal;
        } else {
            return true;
        }
        Iterator it = principals.iterator();
        boolean active = false;
        while (it.hasNext()) {
            Principal principal = (Principal) it.next();

            if (rolePrincipal.equals(principal) && ((RolePrincipal) principal).isActive()) {
                active = true;
                break;
            }
        }
        return active;
    }

}
