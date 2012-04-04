/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2010  Charles Lescot
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * jGuard project home page:
 * http://sourceforge.net/projects/jguard/
 */

package net.sf.jguard.core.authorization.policy;

import com.google.inject.Module;
import com.mycila.testing.plugin.guice.ModuleProvider;
import net.sf.jguard.core.authentication.AuthenticationScope;
import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import net.sf.jguard.core.authentication.manager.MockAuthenticationManagerModule;
import net.sf.jguard.core.authorization.manager.MockAuthorizationManager;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.core.test.JGuardTest;
import net.sf.jguard.core.test.JGuardTestFiles;
import net.sf.jguard.core.test.MockModule;
import org.junit.Test;

import java.net.URL;
import java.security.Permissions;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.List;

import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class JGuardPolicyTest extends JGuardTest {

    protected Policy policy;
    private static final String GRANTED_PERMISSION_NAME = "grantedName";
    private static final String GRANTED_PERMISSION_ACTIONS = "grantedActions";
    private URLPermission grantedPermission = new URLPermission(GRANTED_PERMISSION_NAME, GRANTED_PERMISSION_ACTIONS);
    protected Permissions permissions;


    /**
     * provides a MockAuthenticationManagerModule, which provides a MockAuthenticationManager.
     *
     * @return
     */
    @Override
    protected AuthenticationManagerModule buildAuthenticationManagerModule() {
        URL url = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_AUTHENTICATION_XML.getLabel());
        if (url == null) {
            throw new IllegalStateException(JGuardTestFiles.J_GUARD_AUTHENTICATION_XML.getLabel() + " must be present in the classpath");
        }
        return new MockAuthenticationManagerModule(JGuardTestFiles.JGUARD_STRUTS_EXAMPLE.getLabel(), url);
    }

    @ModuleProvider
    public Iterable<Module> providesModules() {
        URL url = Thread.currentThread().getContextClassLoader().getResource(".");
        List<Module> modules = super.providesModules(AuthenticationScope.LOCAL, true,
                url,
                MockAuthorizationManager.class);
        modules.add(new MockModule());
        return modules;
    }


    public void setUp() {
        permissions = new Permissions();
        permissions.add(grantedPermission);

    }


    @Test
    public void test_granted_permissions_present_in_get_permissions_collection() {

        ProtectionDomain protectionDomain = this.getClass().getProtectionDomain();
        assertTrue(policy.getPermissions(protectionDomain).implies(grantedPermission));
    }
}
