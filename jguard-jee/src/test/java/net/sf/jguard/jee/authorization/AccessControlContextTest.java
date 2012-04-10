/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name: v080beta1 $
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
package net.sf.jguard.jee.authorization;

import groovy.lang.GroovyShell;
import groovy.security.GroovyCodeSourcePermission;
import junit.framework.Assert;
import junit.framework.TestCase;
import net.sf.jguard.core.authorization.domaincombiners.AccessControlContextUtils;
import net.sf.jguard.core.authorization.permissions.RolePrincipal;
import org.codehaus.groovy.control.CompilationFailedException;

import java.security.*;
import java.util.HashSet;

public class AccessControlContextTest extends TestCase {


    /*
      * Test method for 'net.sf.jguard.ext.authorization.AuthorizationUtils.getRestrictedAccessControlContext(Principal)'
      */
    public void getRestrictedAccessControlContext() {
        final String scriptText = "System.exit(0);";
        final GroovyShell gs = new GroovyShell();
        AccessControlContext acc;
        RolePrincipal principal = new RolePrincipal("toto", "sdfsdf");
        principal.setPermissions(new HashSet());
        principal.addPermission(new GroovyCodeSourcePermission("totos"));
        principal.addPermission(new SecurityPermission("createAccessControlContext"));

        acc = AccessControlContextUtils.getRestrictedAccessControlContext(principal);
        // System.setSecurityManager(new SecurityManager());
        try {
            AccessController.doPrivileged(
                    new PrivilegedAction() {
                        public Object run() {
                            Object scriptResult = null;
                            try {
                                // System.setSecurityManager(new SecurityManager());
                                scriptResult = gs.evaluate(scriptText);
                            } catch (CompilationFailedException e) {
                                TestCase.fail(e.getMessage());
                            }
                            return scriptResult;
                        }
                    }, acc);
        } catch (AccessControlException ace) {
            System.out.println(" restricted area! OK");

            return;

        }

        Assert.fail(" an accessControlException should be thrown to prevent security operations done by scripting languages ");
    }

    public void testDummy() {

    }
}
