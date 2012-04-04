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
package net.sf.jguard.core.authentication.exception;

/**
 * Exception raised during Authentication operations.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net ">Charles Lescot</a>
 */
public class AuthenticationException extends RuntimeException {

    /**
     * serial version number.
     */
    private static final long serialVersionUID = 3256720697601832753L;

    /**
     * Constructor for DAOException.
     */
    protected AuthenticationException() {
        super();

    }

    /**
     * Constructor for DAOException with error message.
     *
     * @param message The custom error message
     */
    public AuthenticationException(String message) {
        super(message);

    }

    /**
     * Constructor for DAOException with error message and root  Exception.
     *
     * @param message The custom error message
     * @param cause   The root exception
     */
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);

    }

    /**
     * Constructor for DAOException with the root Exception.
     *
     * @param cause The root exception
     */
    public AuthenticationException(Throwable cause) {
        super(cause);

    }

}
