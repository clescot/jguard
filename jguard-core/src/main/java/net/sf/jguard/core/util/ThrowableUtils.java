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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Locale;
import java.util.ResourceBundle;


/**
 * Utility class for Throwable.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public final class ThrowableUtils {

    private static final Logger logger = LoggerFactory.getLogger(ThrowableUtils.class);

    private ThrowableUtils() {

    }

    /**
     * add Localization for Throwable thrown.
     *
     * @param le     {@link Locale} used to translate message of the exception.
     * @param locale locale to use to localize message
     * @return
     */
    public static Throwable localizeThrowable(Throwable le, Locale locale) {

        Class throwableClass = le.getClass();
        Class[] clazz = new Class[]{String.class};
        try {
            Constructor constructor = throwableClass.getConstructor(clazz);
            ResourceBundle rb = ResourceBundleUtils.getResourceBundle(locale);
            Throwable localizedThrowable = new LocalizedThrowable(le, rb);
            return (Throwable) constructor.newInstance(localizedThrowable.getLocalizedMessage());
        } catch (SecurityException e) {
            logger.error("we cannot localize LoginException for security resitrictions");
            return le;
        } catch (NoSuchMethodException e) {
            logger.error("we cannot localize LoginException method not found ");
            return le;
        } catch (IllegalArgumentException e) {
            logger.error("we cannot localize LoginException arguments are illegal ");
            return le;
        } catch (InstantiationException e) {
            logger.error("we cannot localize LoginException we cannot instantiate the wrapped exception ");
            return le;
        } catch (IllegalAccessException e) {
            logger.error("we cannot localize LoginException we cannot access to the exception ");
            return le;
        } catch (InvocationTargetException e) {
            logger.error("we cannot localize LoginException we cannot invoke the exception ");
            return le;
        }
    }


}
