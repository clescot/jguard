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

package net.sf.jguard.core.authorization.protocol;

import java.util.Arrays;
import java.util.Collection;

/**
 *describe HTTP protocol.
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HTTPProtocol implements Protocol{
    
    private static final String SCHEME ="http";
    private static final String METHODS ="DELETE,GET,HEAD,OPTIONS,POST,PUT,TRACE";
    //CONNECT  method for proxy? => http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9.9
    private static final Collection methodsCollection = Arrays.asList(METHODS.split(","));
   
    public String getScheme(){
        return SCHEME;
    }
  
    public final Collection getMethods() {
        return methodsCollection;
    }
    
}
