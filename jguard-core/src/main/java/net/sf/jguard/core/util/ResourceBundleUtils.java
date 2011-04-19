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
package net.sf.jguard.core.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;


/**
 * Utility class for ResourceBundle.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
final class ResourceBundleUtils {

    private static final String JGUARD = "JGuard";
    private static final String JGUARD_FAILSAFE = "JGuard-failsafe";
    private static final Logger logger = LoggerFactory.getLogger(ResourceBundleUtils.class);


    private ResourceBundleUtils() {

    }

    /**
     * load a ResourceBundle with the name JGuard. If no one is FOudn,
     * a <i>failsafe</i> resourceBundle contained in the jGUard jar is used.
     *
     * @param locale
     * @return
     */
    public static ResourceBundle getResourceBundle(Locale locale) {
        ResourceBundle resourceBundle = null;
        try {
            resourceBundle = ResourceBundle.getBundle(ResourceBundleUtils.JGUARD, locale);
        } catch (MissingResourceException e) {
            // there is not specific bundle to get messages, take the failsafe one and inform to user
            logger.warn("There is not specific bundle to get messages: create a JGuard.properties and copy it to your application base classpath");
            resourceBundle = ResourceBundle.getBundle(ResourceBundleUtils.JGUARD_FAILSAFE, locale);
        }

        return resourceBundle;
    }
}
