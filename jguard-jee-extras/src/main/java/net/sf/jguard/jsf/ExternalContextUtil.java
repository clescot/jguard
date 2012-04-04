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

package net.sf.jguard.jsf;

import net.sf.jguard.jee.util.ContextUtil;

import javax.faces.context.ExternalContext;
import javax.portlet.PortletContext;
import javax.servlet.ServletContext;

public class ExternalContextUtil {

    /**
     * return the <b>absolute</b> path of the resource decribed with the
     * <b>relative</b> path in parameter. absolute path ends with a slash.
     *
     * @param externalContext can be a ServletContext or a PortletContext
     * @param path            relative path to resolve
     * @return resolved path or null
     */
    public static String getContextPath(ExternalContext externalContext,
                                        String path) {
        String resolvedPath = null;
        if (ServletContext.class.isAssignableFrom(externalContext.getContext().getClass())) {
            ServletContext context = (ServletContext) externalContext.getContext();
            resolvedPath = ContextUtil.getContextPath(context, path).toString();
        } else if (PortletContext.class.isAssignableFrom(externalContext.getContext().getClass())) {
            PortletContext context = (PortletContext) externalContext.getContext();
            resolvedPath = ContextUtil.getContextPath(context, path);
        }
        return resolvedPath;
    }

    /**
     * @param externalContext can be a ServletContext or a PortletContext
     * @param key key to set in the external context
     * @param value value in the external context
     */
    public static void setAttribute(ExternalContext externalContext, String key,
                                    Object value) {

        if (ServletContext.class.isAssignableFrom(externalContext.getContext().getClass())) {
            ServletContext context = (ServletContext) externalContext.getContext();
            context.setAttribute(key, value);
        } else if (PortletContext.class.isAssignableFrom(externalContext.getContext().getClass())) {
            PortletContext context = (PortletContext) externalContext.getContext();
            context.setAttribute(key, value);
		}
		
	}

}
