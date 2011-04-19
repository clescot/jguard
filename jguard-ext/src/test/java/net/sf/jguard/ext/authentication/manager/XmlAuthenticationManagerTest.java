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
package net.sf.jguard.ext.authentication.manager;

import com.google.inject.Inject;
import com.google.inject.Module;
import com.mycila.testing.plugin.guice.Bind;
import com.mycila.testing.plugin.guice.ModuleProvider;
import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import net.sf.jguard.core.authentication.manager.AuthenticationXmlStoreFileLocation;
import net.sf.jguard.core.test.AuthenticationManagerTest;
import net.sf.jguard.core.test.JGuardTestFiles;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;


public class XmlAuthenticationManagerTest extends AuthenticationManagerTest {

    @Bind
    protected String applicationName = JGuardTestFiles.JGUARD_STRUTS_EXAMPLE.getLabel();
    protected final URL authenticationXmlFileLocation = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_USERS_PRINCIPALS_XML.getLabel());
    @Inject
    @AuthenticationXmlStoreFileLocation
    private URL fileLocation;


    @Before
    public void setUp() throws Exception {


    }

    @After
    public void tearDown() throws Exception {
    }

    @ModuleProvider
    public Iterable<Module> providesAuthenticationManagerModule() {
        List<Module> modules = new ArrayList<Module>();
        modules.add(buildAuthenticationManagerModule());
        return modules;

    }

    protected Module buildAuthenticationManagerModule() {
        return new AuthenticationManagerModule(applicationName, authenticationXmlFileLocation, XmlAuthenticationManager.class);
    }


    @Test(expected = IllegalStateException.class)
    public void testWhenApplicationNameDoesNotMatch(){
        applicationName = "weirdApplicatioName";
        XmlAuthenticationManager xmlAuthenticationManager = new XmlAuthenticationManager(applicationName, fileLocation);
    }


}
