
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

package net.sf.jguard.ext.authorization.manager;

import com.google.inject.Injector;
import com.google.inject.Module;
import com.google.inject.persist.PersistService;
import com.google.inject.persist.jpa.JpaPersistModule;
import com.mycila.testing.junit.MycilaJunitRunner;
import com.mycila.testing.plugin.guice.ModuleProvider;
import net.sf.jguard.core.authorization.AuthorizationModule;
import net.sf.jguard.core.authorization.AuthorizationScope;
import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;

import javax.inject.Inject;
import javax.persistence.EntityManagerFactory;
import java.util.List;
import java.util.Map;

@RunWith(MycilaJunitRunner.class)
public class JPAAuthorizationManagerTest extends AuthorizationManagerTest {


    private static final String JGUARD_AUTHORIZATION = "jguard-authorization";
    @Inject
    private  Injector injector;
    private PersistService persistService;
 

    @Before
    public  void setUp(){
        persistService = injector.getInstance(PersistService.class);
        persistService.start();
        EntityManagerFactory entityManagerFactory = injector.getInstance(EntityManagerFactory.class);
        Map<String, Object> properties = entityManagerFactory.getProperties();
    }

    @After
    public  void tearsDown(){
        persistService.stop();
    }
   
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


        JpaPersistModule jpaPersistModule =new JpaPersistModule(JGUARD_AUTHORIZATION);
        modules.add(jpaPersistModule);
        return modules;
    }
}
