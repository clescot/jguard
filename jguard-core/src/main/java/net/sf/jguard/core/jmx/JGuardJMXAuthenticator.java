/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name:  $
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
package net.sf.jguard.core.jmx;

import net.sf.jguard.core.PolicyEnforcementPointOptions;
import net.sf.jguard.core.principals.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.remote.JMXAuthenticator;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.util.Set;

/**
 * JGuardJMXAuthenticator is a custom JMX authenticator.
 * It logs the user connecting from JMX.
 * In jee (and jee only !), it adds a special Principal to the Subject created during the login.
 * This is a <code>JMXPrincipal</code> which keeps a reference to the classloader
 * to identify the webapp the user is login in and thus get the correct permission provider
 * from the MultipleAppPolicy.
 *
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 * @since 1.0
 */
public class JGuardJMXAuthenticator implements JMXAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(JGuardJMXAuthenticator.class.getName());

    private String applicationName;
    private ClassLoader classLoader; // only used in jee
    private Configuration configuration = null;
    public static String JGUARD_APPLICATION_NAME = "net.sf.jguard.application.name";

    /**
     * Creates a JGuardJMXAuthentication <strong>for standalone applications</strong>
     * Retrieves the application name from system properties :
     * <ul>
     * <li>net.sf.jguard.application.name</li>
     * <li>or com.sun.management.jmxremote.login.config</li>
     * </ul>
     */
    public JGuardJMXAuthenticator() {

        logger.info("JGuardJMXAuthentication for j2se environnement");
        String appNameProp = System.getProperty(JGUARD_APPLICATION_NAME);
        if (appNameProp != null) {
            // use system property net.sf.jguard.application.name
            applicationName = appNameProp;
        } else {
            //use default applicationName
            applicationName = PolicyEnforcementPointOptions.DEFAULT_APPLICATION_NAME.getLabel();
        }
    }


    /**
     * Creates a JGuardJMXAuthenticator <strong>for jee applications</strong>
     *
     * @param applicationName - the webapp name
     * @param classLoader     - the classloader identifying the permissionProvider in MultipleAppPolicy
     */
    public JGuardJMXAuthenticator(String applicationName, ClassLoader classLoader) {
        logger.info("JGuardJMXAuthentication for jee environnement");
        this.applicationName = applicationName;
        this.classLoader = classLoader;
    }


    public JGuardJMXAuthenticator(String appName, ClassLoader contextClassLoader, Configuration conf) {
        logger.info("JGuardJMXAuthentication for jee environnement");
        logger.info("authentication scope is local");
        this.applicationName = appName;
        this.classLoader = contextClassLoader;
        if(conf==null){
            throw new IllegalArgumentException("configuration is null");
        }
        configuration = conf;
    }

    public Subject authenticate(Object credentials) {

        Subject subject = null;
        if(credentials==null){
            throw new IllegalArgumentException("credentials are null or empty. authentication cannot be done");
        }
        if (configuration == null) {
            try {
                //like configuration is null, we hope that a global configuration has been set
                //and grabbed by the logincontext constructor
                logger.info("logging in application : " + applicationName);
                LoginContext lc = new LoginContext(applicationName, new JMXCallbackHandler((String[]) credentials));
                lc.login();
                subject = lc.getSubject();
            } catch (LoginException e) {
                logger.error("loginException : " + e.getMessage());
                throw new SecurityException(e.getMessage(), e);
            }catch (SecurityException sex){
                 logger.error("SecurityException : " + sex.getMessage());
                throw sex;
            }
        } else {
            //'local' mode
            try {
                LoginContext loginContext = new LoginContext(applicationName, new Subject(), new JMXCallbackHandler((String[]) credentials), configuration);
                loginContext.login();
                subject = loginContext.getSubject();
            } catch (LoginException e) {
                logger.error("loginException : " + e.getMessage());
                throw new SecurityException(e.getMessage(), e);
            }
        }


        if (this.classLoader != null) {
            // used in jee with MultipleAppPolicy
            JMXPrincipal classLoaderPrincipal = new JMXPrincipal(applicationName, this.classLoader);
            subject.getPrincipals().add(classLoaderPrincipal);
        }

        // used in ABAC permissions
        subject.getPrincipals().add(new UserPrincipal(subject));

        if (logger.isDebugEnabled()) {
            logger.debug("Principals set during login :");
            Set ppals = subject.getPrincipals();

            for (Object ppal1 : ppals) {
                Principal ppal = (Principal) ppal1;
                logger.debug(ppal.toString());
            }
        }

        return subject;
    }
}
