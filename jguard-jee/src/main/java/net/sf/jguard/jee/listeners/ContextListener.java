/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.

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
package net.sf.jguard.jee.listeners;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Module;
import com.google.inject.servlet.GuiceServletContextListener;
import com.google.inject.servlet.ServletModule;
import net.sf.jguard.core.FilterChainModule;
import net.sf.jguard.core.authentication.AuthenticationModule;
import net.sf.jguard.core.authentication.AuthenticationScope;
import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import net.sf.jguard.core.authorization.AuthorizationModule;
import net.sf.jguard.core.authorization.AuthorizationScope;
import net.sf.jguard.core.authorization.manager.AuthorizationManager;
import net.sf.jguard.core.authorization.policy.MultipleAppPolicy;
import net.sf.jguard.core.jmx.JMXModule;
import net.sf.jguard.core.jmx.JMXParameters;
import net.sf.jguard.ext.SecurityConstants;
import net.sf.jguard.ext.authentication.manager.AbstractAuthenticationManager;
import net.sf.jguard.ext.authentication.manager.XmlAuthenticationManager;
import net.sf.jguard.ext.authorization.manager.XmlAuthorizationManager;
import net.sf.jguard.jee.HttpConstants;
import net.sf.jguard.jee.util.ContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Policy;
import java.util.ArrayList;
import java.util.Collection;


/**
 * initialize authentication and authorization engines in jGuard.
 * it needs to be be declared in the web.xml file, to be called by the servlet engine lifecycle
 * <b>BEFORE</b> servlet filters and servlets.
 * it permits to initialize Authentication and Authorization <b>only once</b>, for potentially
 * multiple server side technologies used in cunjunction.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 */
public abstract class ContextListener extends GuiceServletContextListener {

    protected Injector injector;
    private static final Logger logger = LoggerFactory.getLogger(ContextListener.class);
    private static final String SLASH = "/";

    private Class<? extends AuthorizationManager> authorizationManagerClass = XmlAuthorizationManager.class;
    private String applicationName;
    private URL authenticationXmlFileLocation;
    private URL filterConfigurationLocation;
    private AuthenticationScope authenticationScope = AuthenticationScope.LOCAL;
    private boolean propagateThrowable = false;
    private URL applicationPath;
    private URL authenticationConfigurationURL;
    private URL authorizationConfigurationURL;

    private String rmiRegistryHost;
    private int rmiRegistryPort;
    private String mbeanServerForConnector;
    private boolean enableJMX;
    private static String defaultConfigurationDirectoryValue = "/WEB-INF/conf/jGuard/";
    private static final String J_GUARD_USERS_PRINCIPALS_XML = "jGuardUsersPrincipals.xml";

    private static final String J_GUARD_FILTER_XML = "jGuardFilter.xml";
    public static final String FILTER_LOCATION = "filterLocation";
    private static final String APPLICATION_NAME_IS_MISSING = " ServletContext.getServletContextName() return null \n you should fix your web.xml by adding the 'display-name' markup with the name of your webapp ";
    private static final String INIT_PARAMETER_IS_NULL = " init parameter is null";
    private static final String CONFIGURATION_DIRECTORY = "configurationDirectory";
    private static final String DEFAULT_CONFIGURATION_DIRECTORY = "defaultConfigurationDirectory";


    /**
     * method called when the webapp start.
     * install jGuard overall Configuration and Policy.
     * put Guice injector in the servlet context.
     *
     * @see javax.servlet.ServletContextListener#contextInitialized(javax.servlet.ServletContextEvent)
     */
    public void contextInitialized(ServletContextEvent contextEvent) {
        logger.debug("#####  initializing ContextListener ... #####");

        ServletContext context = contextEvent.getServletContext();
        applicationPath = ContextUtil.getContextPath(context, SLASH);
        applicationName = context.getServletContextName();
        if (applicationName.startsWith(SLASH)) {
            applicationName = applicationName.replaceFirst(SLASH, "");
        }
        if (applicationName == null) {
            logger.error(APPLICATION_NAME_IS_MISSING);
            throw new IllegalStateException(APPLICATION_NAME_IS_MISSING);
        }

        if (!defaultConfigurationDirectoryValue.endsWith("/")) {
            defaultConfigurationDirectoryValue = defaultConfigurationDirectoryValue + "/";
        }


        //filterConfigurationLocation
        filterConfigurationLocation = getLocation(
                FILTER_LOCATION,
                defaultConfigurationDirectoryValue + J_GUARD_FILTER_XML,
                context);
        if (filterConfigurationLocation == null) {
            throw new IllegalArgumentException(FILTER_LOCATION + INIT_PARAMETER_IS_NULL);
        }
        checkFileExists(filterConfigurationLocation);


        //authenticationXmlFileLocation
        authenticationXmlFileLocation = getLocation(
                AbstractAuthenticationManager.AUTHENTICATION_XML_FILE_LOCATION,
                defaultConfigurationDirectoryValue + J_GUARD_USERS_PRINCIPALS_XML,
                context);

        if (authenticationXmlFileLocation == null) {
            throw new IllegalArgumentException(AbstractAuthenticationManager.AUTHENTICATION_XML_FILE_LOCATION + INIT_PARAMETER_IS_NULL);
        }
        checkFileExists(authenticationXmlFileLocation);


        //authorizationConfigurationURL
        authorizationConfigurationURL = getLocation(
                HttpConstants.AUTHORIZATION_CONFIGURATION_LOCATION,
                HttpConstants.DEFAULT_AUTHORIZATION_CONFIGURATION_LOCATION,
                context);
        if (authorizationConfigurationURL == null) {
            throw new IllegalArgumentException(HttpConstants.AUTHORIZATION_CONFIGURATION_LOCATION + INIT_PARAMETER_IS_NULL);
        }
        checkFileExists(authorizationConfigurationURL);


        //authenticationConfigurationURL
        authenticationConfigurationURL = getLocation(
                HttpConstants.AUTHENTICATION_CONFIGURATION_LOCATION,
                HttpConstants.DEFAULT_AUTHENTICATION_CONFIGURATION_LOCATION,
                context);

        if (authenticationConfigurationURL == null) {
            throw new IllegalArgumentException(HttpConstants.AUTHENTICATION_CONFIGURATION_LOCATION + INIT_PARAMETER_IS_NULL);
        }
        checkFileExists(authenticationConfigurationURL);


        //JMX
        //rmiRegistryHost
        rmiRegistryHost = JMXParameters.DEFAULT_RMI_REGISTRY_HOST.getLabel();
        if (context.getInitParameter(JMXParameters.RMI_REGISTRY_HOST.getLabel()) != null) {
            rmiRegistryHost = context.getInitParameter(JMXParameters.RMI_REGISTRY_HOST.getLabel());
        }

        //rmiRegistryPort
        rmiRegistryPort = JMXParameters.DEFAULT_RMI_REGISTRY_PORT.getValue();
        if (context.getInitParameter(JMXParameters.RMI_REGISTRY_PORT.getLabel()) != null) {
            rmiRegistryPort = Integer.parseInt(context.getInitParameter(JMXParameters.RMI_REGISTRY_PORT.getLabel()));
        }


        mbeanServerForConnector = context.getInitParameter(JMXParameters.MBEAN_SERVER_FOR_CONNECTOR.getLabel());
        enableJMX = Boolean.parseBoolean(context.getInitParameter(JMXParameters.MBEAN_SERVER_FOR_CONNECTOR.getLabel()));

        

        injector = getInjector();

        context.setAttribute(Injector.class.getName(), injector);
        logger.debug("#####  ContextListener initialized  #####");

    }

    private void checkFileExists(URL filterConfigurationLocation) {
        try {
            File filterConfigurationFile = new File(filterConfigurationLocation.toURI());
            if (!filterConfigurationFile.exists() || filterConfigurationFile.isDirectory()) {
                logger.error("configuration url =" + filterConfigurationLocation + "does not point to a config file");
                throw new IllegalStateException("configuration url =" + filterConfigurationLocation + "does not point to a config file");
            }
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }


    /**
     * method called when the webapp shutdown:
     * this method unregister the webapp in the JGuardPolicy repository.
     *
     * @see javax.servlet.ServletContextListener#contextDestroyed(javax.servlet.ServletContextEvent)
     */
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        logger.debug(" context destroyed ");
        ServletContext context = servletContextEvent.getServletContext();
        context.removeAttribute(Injector.class.getName());
        super.contextDestroyed(servletContextEvent);

        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        if (Policy.getPolicy() instanceof MultipleAppPolicy) {
            MultipleAppPolicy policy = (MultipleAppPolicy) Policy.getPolicy();
            policy.unregisterPermissionProvider(contextClassLoader);
        }

        context.removeAttribute(SecurityConstants.CAPTCHA_SERVICE);
    }


    /**
     * resolve location in servlet context, according to the servlet context,
     * the default location if a custom init parameter does not override it.
     *
     * @param initParameterName init parameter name
     * @param defaultLocation   default location if init parameter is not present
     * @param context           context related to this webapp
     * @return resolved location
     */
    private URL getLocation(String initParameterName, String defaultLocation, ServletContext context) {
        URL location;
        if (context.getInitParameter(initParameterName) != null) {
            location = ContextUtil.getContextPath(context, context.getInitParameter(initParameterName));
        } else {
            location = ContextUtil.getContextPath(context, defaultLocation);
        }

        return location;
    }

    @Override
    protected Injector getInjector() {

        Collection<Module> modules = new ArrayList<Module>();
        modules.add(getServletModule());
        modules.add(new AuthenticationManagerModule(applicationName, authenticationXmlFileLocation, XmlAuthenticationManager.class));
        modules.add(new FilterChainModule(propagateThrowable));
        modules.add(new AuthenticationModule(
                authenticationScope,
                authenticationConfigurationURL,
                filterConfigurationLocation));
        modules.add(new AuthorizationModule(
                AuthorizationScope.LOCAL,
                authorizationManagerClass,
                authorizationConfigurationURL,
                applicationPath));
        modules.add(getTechnologySpecificModule());

        if (enableJMX) {
            modules.add(new JMXModule(rmiRegistryHost, rmiRegistryPort));
        }
        injector = Guice.createInjector(modules);
        return injector;


    }

    public abstract ServletModule getServletModule();

    public abstract Module getTechnologySpecificModule();


}
