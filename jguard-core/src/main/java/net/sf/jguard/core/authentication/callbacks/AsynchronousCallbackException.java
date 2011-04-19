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
package net.sf.jguard.core.authentication.callbacks;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * Exception to signal that the current CallbackHandler need to interact with the client(i.e the user), 
 * to grab more informations to populate some callbacks. This exception inherits from UnsupportedCallbackException
 * to respect javadoc from callbackHandler, and to highlight the callback (or more but javadoc only permits one)
 * which need one more interaction with the client. This exception will be grabbed from the LoginModule and 
 * rethrown as a special LoginException subclass.
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @since 1.1
 * @see UnsupportedCallbackException
 * @see CallbackHandler
 */
public class AsynchronousCallbackException extends UnsupportedCallbackException{

   
   public AsynchronousCallbackException(Callback callback){
        super(callback);
    }
    
    /**
     * 
     * @param callback
     * @param message
     */
    public AsynchronousCallbackException(Callback callback,String message){
        super(callback,message);
    }
   
}
