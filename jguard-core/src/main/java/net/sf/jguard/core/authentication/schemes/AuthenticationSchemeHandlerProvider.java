/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2009  Charles GAY
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * jGuard project home page:
 * http://sourceforge.net/projects/jguard/
 */

package net.sf.jguard.core.authentication.schemes;

import javax.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import net.sf.jguard.core.technology.Scopes;
import net.sf.jguard.core.util.XMLUtils;
import org.dom4j.Document;
import org.dom4j.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.util.*;

/**
 * build AuthenticationSchemeHandler with instructions from a configuration file.
 *
 * @param <Request>
 * @param <Response>
 */
@Singleton
public abstract class AuthenticationSchemeHandlerProvider<Request, Response> implements Provider<List<AuthenticationSchemeHandler<Request, Response>>> {
    private static final String CLASS_NAME = "className";
    private static final String PARAMETER = "parameter";
    private static final String KEY = "key";
    private static final String VALUE = "value";

    private static final String J_GUARD_FILTER_2_0_0_XSD = "jGuardFilter_2.0.0.xsd";
    private static Logger logger = LoggerFactory.getLogger(AuthenticationSchemeHandlerProvider.class.getName());
    private List<AuthenticationSchemeHandler<Request, Response>> authSchemeHandlers;
    private Scopes scopes;
    public static final String AUTHENTICATION_SCHEME_HANDLER = "authenticationSchemeHandler";

    @Inject
    public AuthenticationSchemeHandlerProvider(@FilterConfigurationLocation URL filterLocation,
                                               Scopes scopes) {
        this.scopes = scopes;
        this.authSchemeHandlers = loadFilterConfiguration(filterLocation);
    }

    public List<AuthenticationSchemeHandler<Request, Response>> get() {
        return authSchemeHandlers;
    }

    /**
     * load configuration from an XML file.
     *
     * @param configurationLocation
     * @return Map containing filter configuration
     */
    private List<AuthenticationSchemeHandler<Request, Response>> loadFilterConfiguration(URL configurationLocation) {
        URL schemaURL = Thread.currentThread().getContextClassLoader().getResource(J_GUARD_FILTER_2_0_0_XSD);
        Document doc = XMLUtils.read(configurationLocation, schemaURL);

        Element callbackHandlerElement = doc.getRootElement();
        if (doc == null || callbackHandlerElement == null) {
            throw new IllegalArgumentException(" xml file at this location:" + configurationLocation + " is not found or cannot be read ");
        }
        List<AuthenticationSchemeHandler<Request, Response>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<Request, Response>>(1);

        Iterator it = callbackHandlerElement.elementIterator(AUTHENTICATION_SCHEME_HANDLER);
        while (it.hasNext()) {
            Element authenticationSchemeHandlerElement = (Element) it.next();
            String className = authenticationSchemeHandlerElement.attributeValue(CLASS_NAME);
            Iterator itParameters = authenticationSchemeHandlerElement.elementIterator(PARAMETER);
            Map<String, String> parameters = new HashMap<String, String>(2);
            while (itParameters.hasNext()) {
                Element parameterElement = (Element) itParameters.next();
                String key = parameterElement.attributeValue(KEY);
                String value = parameterElement.attributeValue(VALUE);
                parameters.put(key, value);
            }
            Class<AuthenticationSchemeHandler> authenticationSchemeHandlerClass;
            try {
                authenticationSchemeHandlerClass = (Class<AuthenticationSchemeHandler>) Thread.currentThread().getContextClassLoader().loadClass(className);
            } catch (ClassNotFoundException ex) {
                logger.error("authenticationSchemeHandler className cannot be found " + ex.getMessage(), ex);
                continue;
            }
            AuthenticationSchemeHandler authenticationSchemeHandler;
            try {
                Constructor constructor = authenticationSchemeHandlerClass.getConstructors()[0];

                authenticationSchemeHandler = (AuthenticationSchemeHandler) constructor.newInstance(parameters, scopes);
                authenticationSchemeHandlers.add(authenticationSchemeHandler);
            } catch (InstantiationException ex) {
                logger.error("authenticationSchemeHandler cannot be instantiated " + ex.getMessage(), ex);
            } catch (IllegalAccessException ex) {
                logger.error("authenticationSchemeHandler class cannot be accessed" + ex.getMessage(), ex);
            } catch (InvocationTargetException ex) {
                logger.error(ex.getMessage(), ex);
            } catch (SecurityException ex) {
                logger.error(ex.getMessage(), ex);
            }

        }
        if (authenticationSchemeHandlers.size() == 0) {
            throw new IllegalStateException(" the configuration File " + configurationLocation + " does not contains any authenticationSchemeHandler ");
        }
        return authenticationSchemeHandlers;
    }
}
