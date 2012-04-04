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
package net.sf.jguard.ext.util;

import javax.naming.ldap.Control;

/**
 * control which refers to the <a href="<a href="http://msdn.microsoft.com/library/default.asp?url=/library/en-us/ldap/ldap/ldap_server_fast_bind_oid.asp">Active Directory fast bind mode</a>.
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 *
 */
public class FastBindConnectionControl implements Control {

	private static final long serialVersionUID = 3061396984734192249L;

	public byte[] getEncodedValue() {
		return null;
	}

	public String getID() {
		return "1.2.840.113556.1.4.1781";
	}

	public boolean isCritical() {
		return true;
	}

}
