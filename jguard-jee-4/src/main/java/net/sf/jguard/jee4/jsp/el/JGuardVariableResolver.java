/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name:  $
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

package net.sf.jguard.jee4.jsp.el;

import javax.servlet.jsp.el.ELException;
import javax.servlet.jsp.el.VariableResolver;

/**
 * Bind variable from jstl expression language to jsf expression language.
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles GAY</a>
 */
public class JGuardVariableResolver implements VariableResolver{
    
    /** Creates a new instance of JGuardVariableResolver */
    public JGuardVariableResolver() {
    }

    public Object resolveVariable(String string) throws ELException {
        
        //TODO charles add variable resolver
        // we should look into PermissionUtils to see the solution
        return null;
    }
    
}
