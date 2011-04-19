/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
package net.sf.jguard.ext.authorization;

import com.google.inject.Inject;
import com.google.inject.Module;
import com.mycila.testing.junit.MycilaJunitRunner;
import com.mycila.testing.plugin.guice.Bind;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authorization.manager.AuthorizationManager;
import net.sf.jguard.core.authorization.manager.AuthorizationManagerException;
import net.sf.jguard.core.principals.RolePrincipal;
import net.sf.jguard.core.test.JGuardTestFiles;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.FilePermission;
import java.net.URL;
import java.security.Principal;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
@RunWith(MycilaJunitRunner.class)
public abstract class AuthorizationManagerTest {
    protected final URL authorizationXmlFileLocation = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_AUTHORIZATION_XML.getLabel());
    @Inject
    protected AuthorizationManager auth;
    private static final String DUMMY_PRINCIPAL_NAME = "myLocalName";
    private static final String DUMMY_APPLICATION_NAME = "myApplicationName";
    private static final String DUMMY_DOMAIN_NAME = "dummyDomainName";
    private static final String DUMMY_DOMAIN_NAME_2 = "dummyDomainName2";
    private static final String READ_FILE_PERMISSION_ACTION = "read";
    private static final String CURRENT_DIRECTORY_LOCATION = ".";
    private static final String UNKNOWN_PRINCIPAL_NAME = "qsdqsd";
    private static final String CLONED_PRINCIPAL_NAME = "clonedName";
    private static final String WRITE_FILE_PERMISSION_ACTION = "write";


    public static final String APPLICATION_NAME = "jguard-struts-example";
    @Bind(annotatedBy = ApplicationName.class)
    protected String applicationName = JGuardTestFiles.JGUARD_STRUTS_EXAMPLE.getLabel();

    public abstract Iterable<Module> providesAuthorizationModule();

    @Before
    public void setUp() {

    }
    // principal tests region

    @Test
    public void testUpdateUnknownPrincipal() throws AuthorizationManagerException {

        RolePrincipal principal = new RolePrincipal(DUMMY_PRINCIPAL_NAME, DUMMY_APPLICATION_NAME);
        auth.updatePrincipal(UNKNOWN_PRINCIPAL_NAME, principal);
    }

    @Test
    public void testCreateAndDeletePrincipal() throws AuthorizationManagerException {
        RolePrincipal principal = new RolePrincipal(DUMMY_PRINCIPAL_NAME, DUMMY_APPLICATION_NAME);
        auth.createPrincipal(principal);
        auth.deletePrincipal(principal);
    }

    @Test
    public void testCreateAndUpdatePrincipal() throws AuthorizationManagerException {
        RolePrincipal principal = new RolePrincipal(DUMMY_PRINCIPAL_NAME, DUMMY_APPLICATION_NAME);
        auth.createPrincipal(principal);
        auth.updatePrincipal(principal);
        auth.deletePrincipal(principal);
    }


    @Test
    public void testClonePrincipal() throws AuthorizationManagerException {
        RolePrincipal principal = new RolePrincipal(DUMMY_PRINCIPAL_NAME, DUMMY_APPLICATION_NAME);
        auth.createPrincipal(principal);
        Principal clonedPrincipal = auth.clonePrincipal(DUMMY_PRINCIPAL_NAME, CLONED_PRINCIPAL_NAME);
        auth.deletePrincipal(clonedPrincipal);
        auth.deletePrincipal(principal);
    }




    @Test
    public void testAddToPrincipalAPermission() throws AuthorizationManagerException {
        RolePrincipal principal = new RolePrincipal(DUMMY_PRINCIPAL_NAME, DUMMY_APPLICATION_NAME);
        auth.createPrincipal(principal);

        URL url = Thread.currentThread().getContextClassLoader().getResource(CURRENT_DIRECTORY_LOCATION);
        FilePermission filePermission = new FilePermission(url.toExternalForm(), READ_FILE_PERMISSION_ACTION);
        auth.createPermission(filePermission);


        auth.addToPrincipal(DUMMY_PRINCIPAL_NAME, filePermission);
        auth.deletePrincipal(principal);
        Assert.assertNull(auth.readPrincipal(DUMMY_PRINCIPAL_NAME));
    }



    //permission tests region

    @Test
    public void testCreatePermission() throws AuthorizationManagerException {
        URL url = Thread.currentThread().getContextClassLoader().getResource(CURRENT_DIRECTORY_LOCATION);
        FilePermission filePermission = new FilePermission(url.toExternalForm(), READ_FILE_PERMISSION_ACTION);
        auth.createPermission(filePermission);
        auth.deletePermission(filePermission.getName());
    }

    @Test
    public void testUpdatePermission() throws AuthorizationManagerException {
        URL url = Thread.currentThread().getContextClassLoader().getResource(CURRENT_DIRECTORY_LOCATION);
        FilePermission readFilePErmission = new FilePermission(url.toExternalForm(), READ_FILE_PERMISSION_ACTION);
        auth.createPermission(readFilePErmission);
        FilePermission writeFilePermission = new FilePermission(url.toExternalForm(), WRITE_FILE_PERMISSION_ACTION);
        auth.updatePermission(readFilePErmission.getName(), writeFilePermission);
    }

}
