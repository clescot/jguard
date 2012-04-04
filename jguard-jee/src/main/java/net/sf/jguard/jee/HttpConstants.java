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
package net.sf.jguard.jee;


/**
 * Interface whick regroup all of the <b>HTTP</b> Constants used.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 */
public interface HttpConstants {
    static final String DEBUG = "debug";

    static final String WEBAPP_HOME_PATH = "webappHome";

    //fields names used in FORM authentication
    static final String LOGIN_FIELD = "loginField";
    static final String PASSWORD_FIELD = "passwordField";

    //uri used to configure jGuard in a webapp
    static final String AUTHENTICATION_SUCCEED_URI = "authenticationSucceedURI";
    static final String AUTHENTICATION_FAILED_URI = "authenticationFailedURI";
    static final String LOGON_PROCESS_URI = "logonProcessURI";
    static final String LOGON_URI = "logonURI";
    static final String LOGOFF_URI = "logoffURI";
    static final String REGISTER_PROCESS_URI = "registerProcessURI";
    static final String REGISTER_URI = "registerURI";

    static final String GO_TO_LAST_ACCESS_DENIED_URI_ON_SUCCESS = "goToLastAccessDeniedUriOnSuccess";


    // authentication schemes List
    static final String AUTH_SCHEME = "authScheme";

    //ContextListener locations
    static final String DEFAULT_AUTHENTICATION_CONFIGURATION_LOCATION = "/WEB-INF/conf/jGuard/jGuardAuthentication.xml";
    static final String DEFAULT_AUTHORIZATION_CONFIGURATION_LOCATION = "/WEB-INF/conf/jGuard/jGuardAuthorization.xml";
    static final String AUTHENTICATION_CONFIGURATION_LOCATION = "authenticationConfigurationLocation";
    static final String AUTHORIZATION_CONFIGURATION_LOCATION = "authorizationConfigurationLocation";


}

