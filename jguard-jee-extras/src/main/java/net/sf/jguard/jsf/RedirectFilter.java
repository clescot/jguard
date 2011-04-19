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

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * redirect calls to ressource ending with some extensions like .jsp, to
 * the same url with an authorized extension. the init Parameter
 * is <strong>targetExtension</strong>, and is set by default to <strong>.jsf</strong>.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class RedirectFilter implements Filter {
    private String targetExtension = null;
    private static final String TARGET_EXTENSION = "targetExtension";
    private static final String DEFAULT_TARGET_EXTENSION = ".jsf";

    public void init(FilterConfig filterConfig) throws ServletException {
        targetExtension = filterConfig.getInitParameter(TARGET_EXTENSION);
        if (targetExtension == null) {
            targetExtension = DEFAULT_TARGET_EXTENSION;
        }
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        if (servletRequest instanceof HttpServletRequest) {
            HttpServletRequest request = (HttpServletRequest) servletRequest;
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            String url = request.getRequestURL().toString();
            if (!url.endsWith("/") && !url.endsWith(targetExtension)) {
                int urlLength = url.length();
                String newUrl = url.substring(0, urlLength - targetExtension.length()) + targetExtension;
                response.sendRedirect(newUrl);
                return;
            }
        }

        filterChain.doFilter(servletRequest, servletResponse);

    }

    public void destroy() {

    }

}
