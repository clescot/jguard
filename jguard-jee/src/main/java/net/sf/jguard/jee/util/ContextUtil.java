/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name:  $
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
package net.sf.jguard.jee.util;

import net.sf.jguard.core.util.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.portlet.PortletContext;
import javax.servlet.ServletContext;
import java.net.MalformedURLException;
import java.net.URL;


/**
 * utility class to resolve path in a jee environment.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class ContextUtil {

    private static final String JNDI = "jndi:";
    private static final Logger logger = LoggerFactory.getLogger(ContextUtil.class);
    private static final String SLASH = "/";

    /**
     * resolve the abstract path provided into a real path.
     *
     * @param context
     * @param path    abstract path
     * @return resolved path
     */
    public static URL getContextPath(ServletContext context, String path) {

        URL realPathURL = null;

        if (path == null) {
            throw new IllegalArgumentException("path is null");
        }

        realPathURL = locatePath(path, context);

        if (realPathURL == null) {
            realPathURL = locatePath(".", context);
        }

        if (realPathURL != null && realPathURL.toString().startsWith(JNDI) && context.getRealPath(path) != null) {
            try {
                realPathURL = new URL(context.getRealPath(path));
            } catch (MalformedURLException e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("webappHomePath=" + realPathURL);
        }

        //used to replace blank spaces by '%20' and so on...
        try {
            realPathURL = new URL(XMLUtils.resolveLocation(realPathURL.toString()));
        } catch (MalformedURLException e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        return realPathURL;


    }

    private static URL locatePath(String path, ServletContext context) {
        URL realPath = null;
        //use servletContext.getResource
        try {
            realPath = context.getResource(path);

        } catch (MalformedURLException e) {
            logger.debug(e.getMessage());
        }


        //if getRealPath fails, use the java standard edition way
        if (realPath == null) {
            URL url = Thread.currentThread().getContextClassLoader().getResource(path);
            if (url == null) {
                logger.error(" resource " + path + " cannot be found \n one solution can be to declare a displayname markup in your web.xml with the name of your war archive ");
                return null;
            }
            realPath = url;
        }
        return realPath;

    }

    /**
     * resolve the abstract path provided into a real path.
     *
     * @param context
     * @param path    abstract path
     * @return resolved path
     */
    public static String getContextPath(PortletContext context, String path) {

        URL realPathURL = null;
        String realPath = null;

        //use servletContext.getResource
        try {
            realPathURL = context.getResource(path);

        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }

        if (realPathURL != null) {
            realPath = realPathURL.toString();
        }


        //if getRealPath fails, use the java standard edition way
        if (realPath == null) {
            realPath = Thread.currentThread().getContextClassLoader().getResource(path).toString();
        }

        if (realPath != null && realPath.startsWith(JNDI) && context.getRealPath(path) != null) {
            realPath = context.getRealPath(path);
        }


        if (logger.isDebugEnabled()) {
            logger.debug("webappHomePath=" + realPath);
        }

        //used to replace blank spaces by '%20' and so on...
        realPath = XMLUtils.resolveLocation(realPath);

        return realPath;


    }
}
