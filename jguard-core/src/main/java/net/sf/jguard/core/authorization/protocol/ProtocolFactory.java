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

import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
class ProtocolFactory {

    private static Map schemes = new HashMap();

    /**
     * @param scheme
     * @return Protocol associated with the requested scheme
     */
    public static Protocol getProtocol(String scheme) {
        return (Protocol) schemes.get(scheme);
    }

    public static void registerProtocol(Protocol protocol) {
        if (!schemes.containsKey(protocol.getScheme())) {
            schemes.put(protocol.getScheme(), protocol);
        } else {
            throw new UnsupportedOperationException("a protocol is already registered with this scheme");
        }
    }

}
