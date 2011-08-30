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
import com.mycila.testing.junit.MycilaJunitRunner;
import com.mycila.testing.plugin.guice.Bind;
import com.mycila.testing.plugin.guice.ModuleProvider;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authorization.AuthorizationModule;
import net.sf.jguard.core.authorization.Permission;
import net.sf.jguard.core.authorization.manager.AuthorizationManager;
import net.sf.jguard.core.authorization.manager.AuthorizationManagerException;
import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.authorization.permissions.PermissionUtils;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.core.authorization.policy.ProtectionDomainUtils;
import net.sf.jguard.core.principals.RolePrincipal;
import net.sf.jguard.core.test.JGuardTestFiles;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.inject.Inject;
import java.io.File;
import java.io.FilePermission;
import java.io.IOException;
import java.net.URL;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.*;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
@RunWith(MycilaJunitRunner.class)
public abstract class AuthorizationManagerTest {
    protected final URL authorizationXmlFileLocation = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_AUTHORIZATION_XML.getLabel());
    protected URL applicationPath = Thread.currentThread().getContextClassLoader().getResource(".");

    @Inject
    protected AuthorizationManager auth;
    private static final String DUMMY_PRINCIPAL_NAME = "myLocalName";
    private static final long DUMMY_PRINCIPAL_ID = 3764;
    private static final String DUMMY_APPLICATION_NAME = "myApplicationName";
    private static final String READ_FILE_PERMISSION_ACTION = "read";
    private static final String CURRENT_DIRECTORY_LOCATION = ".";
    private static final String UNKNOWN_PRINCIPAL_NAME = "qsdqsd";
    private static final String CLONED_PRINCIPAL_NAME = "clonedName";
    private static final String WRITE_FILE_PERMISSION_ACTION = "write";


    public static final String APPLICATION_NAME = "jguard-struts-example";
    @Bind(annotatedBy = ApplicationName.class)
    protected String applicationName = JGuardTestFiles.JGUARD_STRUTS_EXAMPLE.getLabel();

    private Random random = new Random();
    private static final String DUMMY_PERMISSION_ACTIONS = "dummyPermissionActions";
    private static final String DUMMY_PERMISSION_NAME = "dummyPermissionName";
    private static final long DUMMY_ID = 444;
    private static final String DUMMY_PERMISSION_NAME_2 = "dummyPermissionName2";
    private static final String DUMMY_PERMISSION_ACTIONS_2 ="sdfsdfsdfsdf" ;


    @ModuleProvider
    protected List<Module> providesAuthorizationModule() {
        List<Module> modules = new ArrayList<Module>();
        modules.add(buildAuthorizationModule());
        return modules;
    }

    protected abstract AuthorizationModule buildAuthorizationModule();


    // principal tests region

    @Test
    public void testUpdateUnknownPrincipal() throws AuthorizationManagerException {

        RolePrincipal principal = new RolePrincipal(DUMMY_PRINCIPAL_NAME, DUMMY_APPLICATION_NAME);
        auth.updatePrincipal(principal);
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
    public void testAddToPrincipal() throws AuthorizationManagerException {

        //create a principal
        RolePrincipal principal = new RolePrincipal(DUMMY_PRINCIPAL_NAME, DUMMY_APPLICATION_NAME);
        auth.createPrincipal(principal);


        //Create a permission
        URL url = Thread.currentThread().getContextClassLoader().getResource(CURRENT_DIRECTORY_LOCATION);
        FilePermission filePermission = new FilePermission(url.toExternalForm(), READ_FILE_PERMISSION_ACTION);
        auth.createPermission(Permission.translateToJGuardPermission(filePermission));

        //add permission alredy persisted to principal
        Permission translatedPermission =Permission.translateToJGuardPermission(filePermission);
        auth.addToPrincipal(principal.getId(), translatedPermission);
        RolePrincipal updatedPrincipal = auth.readPrincipal(principal.getId());
        Assert.assertTrue(updatedPrincipal.getPermissions().contains(translatedPermission));

        //we add to principal a permission not yet persisted in the datastore
        Permission permissionNotYetPersisted = new Permission(URLPermission.class,DUMMY_PERMISSION_NAME,DUMMY_PERMISSION_ACTIONS);
        //permissionNotYetPersisted.setId(DUMMY_ID);
        permissionNotYetPersisted.setRolePrincipal(updatedPrincipal);
        auth.addToPrincipal(updatedPrincipal.getId(),permissionNotYetPersisted);
        RolePrincipal updatedPrincipal2 = auth.readPrincipal(updatedPrincipal.getId());
        Assert.assertTrue(updatedPrincipal2.getPermissions().contains(permissionNotYetPersisted));

        //we check that the permission is persisted with the principal
        Set<Permission> permissions=updatedPrincipal2.getPermissions();
        Permission permissionPersisted = null;
        for (Permission perm:permissions){
            if(URLPermission.class.getName().equals(perm.getClazz())){
                permissionPersisted = perm;
                break;
            }
        }
        Permission permission = auth.readPermission(permissionPersisted.getId());
        Assert.assertTrue(null!=permission);

        RolePrincipal updatedPrincipal3 = auth.readPrincipal(updatedPrincipal2.getId());
        updatedPrincipal3.getPermissions().clear();
        auth.updatePrincipal(updatedPrincipal3);
    }



    //permission tests region

    @Test
    public void testCreatePermission() throws AuthorizationManagerException {
        URL url = Thread.currentThread().getContextClassLoader().getResource(CURRENT_DIRECTORY_LOCATION);
        FilePermission filePermission = new FilePermission(url.toExternalForm(), READ_FILE_PERMISSION_ACTION);
        Permission permission = Permission.translateToJGuardPermission(filePermission);
        auth.createPermission(permission);
        auth.deletePermission(permission);
    }

    @Test
    public void testUpdatePermission() throws AuthorizationManagerException {
        URL url = Thread.currentThread().getContextClassLoader().getResource(CURRENT_DIRECTORY_LOCATION);
        FilePermission readFilePErmission = new FilePermission(url.toExternalForm(), READ_FILE_PERMISSION_ACTION);
        Permission jguardReadPermission = Permission.translateToJGuardPermission(readFilePErmission);
        auth.createPermission(jguardReadPermission);
        FilePermission writeFilePermission = new FilePermission(url.toExternalForm(), WRITE_FILE_PERMISSION_ACTION);
        Permission jguardWritePermission = Permission.translateToJGuardPermission(writeFilePermission);
        jguardWritePermission.setId(jguardReadPermission.getId());
        auth.updatePermission(jguardWritePermission);
    }


    @Test
    public void testUpdatePrincipal() throws AuthorizationManagerException {
        RolePrincipal principal = createDummyPrincipal();
        principal.addPermission(new Permission(URLPermission.class,DUMMY_PERMISSION_NAME,DUMMY_PERMISSION_ACTIONS));

        auth.updatePrincipal(principal);
    }

    @Test
    public void testDeletePermission() throws AuthorizationManagerException {
        URL url = Thread.currentThread().getContextClassLoader().getResource(CURRENT_DIRECTORY_LOCATION);
        FilePermission filePermission = new FilePermission(url.toExternalForm(), READ_FILE_PERMISSION_ACTION);
        Permission permission = Permission.translateToJGuardPermission(filePermission);
        auth.createPermission(permission);
        auth.deletePermission(permission);
    }

    @Test
    public void testDeletePrincipal() throws AuthorizationManagerException {
        RolePrincipal rolePrincipal = createDummyPrincipal();
        auth.deletePrincipal(rolePrincipal);
        Assert.assertNull(auth.readPrincipal(rolePrincipal.getId()));
    }

    @Test
    public void testExportASXmlFile() throws IOException, AuthorizationManagerException {
        auth.exportAsXMLFile(File.createTempFile("temp"+random.nextInt(),null).getAbsolutePath());
    }

    @Test
    public void testExportASXmlString() throws IOException, AuthorizationManagerException {
        String exportedString = auth.exportAsXMLString();
        System.out.println(exportedString);
    }

    @Test
    public void testIsEmpty(){
        auth.isEmpty();
    }


    @Test
    public void testExportAsXmlAuthorizationManager() throws IOException, AuthorizationManagerException {
        XmlAuthorizationManager xmlAuthorizationManager = ((AbstractAuthorizationManager)auth).exportAsXmlAuthorizationManager(File.createTempFile("temp"+random.nextInt(),null).getAbsolutePath());
    }


    @Test
    public void testGetPermission() throws AuthorizationManagerException {
        Permission test = new Permission(URLPermission.class,DUMMY_PERMISSION_NAME,DUMMY_PERMISSION_ACTIONS);
        auth.createPermission(test);
        
        Collection<Long> ids = new ArrayList<Long>();
        ids.add(test.getId());
        Set<Permission> permissions =  auth.getPermissions(ids);
        Assert.assertEquals(1,permissions.size());
        Assert.assertEquals(test.toJavaPermission(), permissions.iterator().next().toJavaPermission());
    }


    @Test
    public void testAddInheritance() throws AuthorizationManagerException {
        RolePrincipal ascendantPrincipal = createDummyPrincipal();
        RolePrincipal descendantPrincipal = createDummyPrincipal();
        auth.addInheritance(ascendantPrincipal.getId(), descendantPrincipal.getId());
        RolePrincipal updatedAscendant = auth.readPrincipal(ascendantPrincipal.getId());
        RolePrincipal updatedDescendant = auth.readPrincipal(descendantPrincipal.getId());
        Assert.assertTrue(updatedAscendant.getDescendants().contains(updatedDescendant));

    }

     @Test
    public void testDeleteInheritance() throws AuthorizationManagerException {
         RolePrincipal ascendantPrincipal = createDummyPrincipal();
         RolePrincipal descendantPrincipal = createDummyPrincipal();
        auth.addInheritance(ascendantPrincipal.getId(),descendantPrincipal.getId());
        RolePrincipal updatedAscendant = auth.readPrincipal(ascendantPrincipal.getId());
        RolePrincipal updatedDescendant = auth.readPrincipal(descendantPrincipal.getId());
        auth.deleteInheritance(updatedAscendant.getId(),updatedDescendant.getId());

    }


    @Test
    public void testListPermissions() throws AuthorizationManagerException {
       int permissionsSize = auth.listPermissions().size();
       Permission permission = new Permission(URLPermission.class,DUMMY_PERMISSION_NAME,DUMMY_PERMISSION_ACTIONS);
       auth.createPermission(permission);
       List<Permission> permissions2= auth.listPermissions();
       Assert.assertTrue(permissions2.size()==permissionsSize+1);
       Assert.assertTrue(permissions2.contains(permission));
    }

    @Test
    public void testListPrincipals() throws AuthorizationManagerException {
       int principalsSize = auth.listPrincipals().size();
        RolePrincipal principal = createDummyPrincipal();
       List<RolePrincipal> principals= auth.listPrincipals();
       Assert.assertTrue(principals.size()==principalsSize+1);
       Assert.assertTrue(principals.contains(principal));
    }

    private RolePrincipal createDummyPrincipal() throws AuthorizationManagerException {
        RolePrincipal principal= new RolePrincipal();
        principal.setApplicationName(DUMMY_APPLICATION_NAME);
        auth.createPrincipal(principal);
        return principal;
    }

    @Test
    public void testReadPrincipal() throws AuthorizationManagerException {
        RolePrincipal rolePrincipal = createDummyPrincipal();
        RolePrincipal rolePrincipal2 = auth.readPrincipal(rolePrincipal.getId());
        Assert.assertEquals(rolePrincipal,rolePrincipal2);
    }

    @Test
    public void testAddAlwaysGrantedPermissions(){
        Permissions permissions = new Permissions();
        URLPermission dummyPermission = new URLPermission(DUMMY_PERMISSION_NAME,DUMMY_PERMISSION_ACTIONS);
        permissions.add(dummyPermission);
        auth.addAlwaysGrantedPermissions(permissions);
        ProtectionDomain protectionDomain = this.getClass().getProtectionDomain();
        Assert.assertTrue(auth.getPermissions(protectionDomain).implies(dummyPermission));
        URLPermission dummyPermission2 = new URLPermission(DUMMY_PERMISSION_NAME_2,DUMMY_PERMISSION_ACTIONS_2);
        Assert.assertFalse(auth.getPermissions(protectionDomain).implies(dummyPermission2));
    }

    @Test
    public void testGetPermissions() throws AuthorizationManagerException {

        RolePrincipal admin = new RolePrincipal();
        admin.setApplicationName(DUMMY_PERMISSION_NAME);
        Set<Permission> permissions = new HashSet<Permission>();
        Permission dummyPermission = createDummyPermission();
        permissions.add(dummyPermission);
        admin.setPermissions(permissions);
        auth.createPrincipal(admin);
        ProtectionDomain protectionDomain = ProtectionDomainUtils.getEmptyProtectionDomain(admin);
        PermissionCollection collection = auth.getPermissions(protectionDomain);
        for(Permission permission:permissions){
            Assert.assertTrue(collection.implies(permission.toJavaPermission()));
        }
    }

    private Permission createDummyPermission() {
        return new Permission(URLPermission.class,DUMMY_PERMISSION_NAME,DUMMY_PERMISSION_ACTIONS);
    }


}
