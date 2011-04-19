/*
 * URLPermissionFactory.java
 *
 * Created on 2 mars 2007, 21:41
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package net.sf.jguard.jee;

import net.sf.jguard.core.authorization.permissions.PermissionFactory;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.core.lifecycle.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.security.Permission;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * return an URLPermission.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class HttpPermissionFactory implements PermissionFactory<HttpServletRequest> {

    static public final Logger logger = LoggerFactory.getLogger(HttpPermissionFactory.class);
    private static Pattern starPattern = Pattern.compile(HttpPermissionFactory.STAR);
    private static final String STAR = "\\*";
    private static final String DOUBLE_STAR = "\\*\\*";
    private static final String PERMISSION_FROM_USER_GENERIC_PERMISSION_NAME = "permissionFromUser";


    public Permission getPermission(Request<HttpServletRequest> requestAdapter) {
        HttpServletRequest request = requestAdapter.get();
        String uriWithQuery = buildRequest(request);
        logger.debug("uriWithQuery=" + uriWithQuery);
        //build the permission corresponding to the URI and prevent any '*' character to be interpreted as a regexp
        StringBuffer actions = new StringBuffer(URLPermission.removeRegexpFromURI(uriWithQuery));
        actions.append(',').append(request.getProtocol()).append(',').append(request.getMethod()).append("permission build from the user request");
        return new URLPermission(PERMISSION_FROM_USER_GENERIC_PERMISSION_NAME, actions.toString());
    }

    private static String buildRequest(HttpServletRequest req) {

        String uriWithQuery;

        String uri = req.getRequestURI();
        String servletPath = req.getServletPath();
        int index = uri.indexOf(servletPath);
        if (-1 == index) {
            throw new IllegalArgumentException("uri does not contains servletPath");
        }
        StringBuffer sb = new StringBuffer(uri.substring(index));

        if (req.getQueryString() != null && req.getQueryString().length() > 0) {
            sb.append("?");
            sb.append(req.getQueryString());
        }
        uriWithQuery = sb.toString();
        Matcher matcher = starPattern.matcher(uriWithQuery);
        uriWithQuery = matcher.replaceAll(HttpPermissionFactory.DOUBLE_STAR);
        logger.debug("uriWithQuery=" + uriWithQuery);
        return uriWithQuery;
    }
}

