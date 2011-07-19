
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

package net.sf.jguard.ext.authorization.manager;

import com.google.inject.Module;
import com.google.inject.persist.jpa.JpaPersistModule;
import com.mycila.testing.junit.MycilaJunitRunner;
import com.mycila.testing.plugin.guice.ModuleProvider;
import net.sf.jguard.core.authorization.AuthorizationModule;
import net.sf.jguard.core.authorization.AuthorizationScope;
import org.junit.runner.RunWith;

import java.util.List;

@RunWith(MycilaJunitRunner.class)
public class JPAAuthorizationManagerTest extends AuthorizationManagerTest {


    @Override
    protected AuthorizationModule buildAuthorizationModule() {

        return new AuthorizationModule(AuthorizationScope.LOCAL,
                JPAAuthorizationManager.class,
                authorizationXmlFileLocation,
                applicationPath);
    }


    @ModuleProvider
    protected List<Module> providesAuthorizationModule() {
       List<Module> modules = super.providesAuthorizationModule();
        modules.add(new JpaPersistModule("jguard-authorization"));
        return modules;
    }
}
