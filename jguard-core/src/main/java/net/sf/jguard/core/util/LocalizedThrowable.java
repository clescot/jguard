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
package net.sf.jguard.core.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.LoginException;
import java.io.Serializable;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Subclass of {@link LoginException} which provide a <strong>localized</strong> message.
 *
 * @author <a href="mailto:tandilero@users.sourceforge.net">Maximiliano Batelli</a>
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class LocalizedThrowable extends Throwable implements Serializable {


    private static final Logger logger = LoggerFactory.getLogger(LocalizedThrowable.class);
    /**
     * serial version number.
     */
    private static final long serialVersionUID = 1L;

    private String errorKey = "";
    private Throwable cause = null;
    private ResourceBundle rb = null;


    /**
     * @param errorKey The error key
     * @param rb       resourceBundle used rto localize message
     */
    public LocalizedThrowable(String errorKey, ResourceBundle rb) {
        this.errorKey = errorKey;
        this.rb = rb;

    }

    /**
     * @param wrappedThrowable The Throwable to wrape to add Localization feature.
     * @param rb               resourcebundle used to localize the message
     */
    public LocalizedThrowable(Throwable wrappedThrowable, ResourceBundle rb) {
        this.errorKey = wrappedThrowable.getMessage();
        this.rb = rb;
    }

    /**
     * @param wrappedThrowable The Throwable to wrape to add Localization feature.
     * @param cause            Throwable which handl the message
     * @param rb               resourcebundle used to localize the message
     */
    public LocalizedThrowable(Throwable wrappedThrowable, Throwable cause, ResourceBundle rb) {
        this.errorKey = wrappedThrowable.getMessage();
        this.cause = cause;
        this.rb = rb;
    }

    /**
     * @param errorKey key of the error in the properties file
     * @param cause    Throwable
     * @param rb       resourceBundle used to localise message
     */
    public LocalizedThrowable(String errorKey, Throwable cause, ResourceBundle rb) {
        this.errorKey = errorKey;
        this.cause = cause;
        this.rb = rb;
    }


    public String getLocalizedMessage() {
        return getLocalizedMessage(this.rb);
    }

    String getLocalizedMessage(ResourceBundle rb) {

        String message;
        try {
            message = rb.getString(errorKey);
        } catch (MissingResourceException e) {
            logger.error("Login error!!! but missing specific error key in bundle: " + errorKey);
            message = errorKey;
        }
        return message;
    }

    /**
     * @return wrapped Throwable
     */
    @Override
    public Throwable getCause() {
        return cause;
    }
}
