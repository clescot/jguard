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

package net.sf.jguard.core.test;


import javax.inject.Inject;
import com.google.inject.Module;
import com.mycila.testing.junit.MycilaJunitRunner;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.principals.*;
import net.sf.jguard.core.util.SubjectUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.net.URL;
import java.security.Principal;
import java.util.*;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */

@RunWith(MycilaJunitRunner.class)
public abstract class AuthenticationManagerTest {
    protected static final String LOGIN = "login";
    private static final String PASSWORD = "password";
    private static final String ACTIVE = "active";

    protected String applicationName = JGuardTestFiles.JGUARD_STRUTS_EXAMPLE.getLabel();
    protected final URL authenticationXmlFileLocation = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_USERS_PRINCIPALS_XML.getLabel());
    @Inject
    protected AuthenticationManager authenticationManager;
    private static final String ID = "id";
    protected final URL url = Thread.currentThread().getContextClassLoader().getResource(JGuardTestFiles.J_GUARD_USERS_PRINCIPALS_XML.getLabel());

    private static Logger logger = LoggerFactory.getLogger(AuthenticationManagerTest.class);
    protected static final String DUMMY_LOGIN = "toto";

    public abstract Iterable<Module> providesAuthenticationManagerModule();

    @Test
    public void testAddAndRemoveRolePrincipal() {
        logger.debug("begin testAddAndRemoveRolePrincipal");
        Organization orga = authenticationManager.findOrganization(AuthenticationManager.SYSTEM);
        RolePrincipal rp = new RolePrincipal("dummyRole", JGuardTestFiles.JGUARD_STRUTS_EXAMPLE.getLabel(), orga);
        try {
            authenticationManager.createPrincipal(rp);
            authenticationManager.deletePrincipal(rp);
        } catch (AuthenticationException aex) {
            Assert.fail(aex.getMessage());
        }
    }

    @Test
    public void testCreateAndRemoveUser() {
        logger.info("begin testCreateAndRemoveUSer");
        String loginAndPassword = DUMMY_LOGIN + System.currentTimeMillis();
        SubjectTemplate st = buildSubjectTemplate(loginAndPassword);
        Subject user = null;

        try {
            Organization orga = authenticationManager.getDefaultOrganization();
            SubjectTemplate stOrga = orga.getSubjectTemplate();
            user = authenticationManager.createUser(st, orga);
        } catch (AuthenticationException e) {
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(user);
        try {
            authenticationManager.deleteUser(user);
            Set<Subject> users = authenticationManager.getUsers();
            assertTrue(!users.contains(user));
        } catch (AuthenticationException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testCreateOrganization() throws CloneNotSupportedException {
        try {

            OrganizationTemplate orgaTemplate = (OrganizationTemplate) authenticationManager.getOrganizationTemplate().clone();
            Collection reqCredentials = orgaTemplate.getCredentials();
            Set<JGuardCredential> newCredentials = new HashSet<JGuardCredential>();
            for (Object reqCredential : reqCredentials) {
                JGuardCredential cred = (JGuardCredential) reqCredential;
                Object value = cred.getValue();
                if (value == null) {
                    value = "";
                }

                newCredentials.add(new JGuardCredential(cred.getName(), value.toString() + System.currentTimeMillis()));
            }
            orgaTemplate.getCredentials().clear();
            orgaTemplate.getCredentials().addAll(newCredentials);
            Set orgas = authenticationManager.getOrganizations();
            authenticationManager.createOrganization(orgaTemplate);
        } catch (AuthenticationException ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCreateUser() {
        logger.info("begin testCreateUser");
        String loginAndPassword = DUMMY_LOGIN + System.currentTimeMillis();
        SubjectTemplate st = buildSubjectTemplate(loginAndPassword);
        Subject user;

        try {
            user = authenticationManager.createUser(st, authenticationManager.getDefaultOrganization());
            logger.info(" test succeed ");

            logger.info(user.toString());
            JGuardCredential cred = SubjectUtils.getIdentityCredential(user, authenticationManager);
            Subject userFound = authenticationManager.findUser(cred.getValue().toString());
            Set principals = user.getPrincipals();
            Set principalsFound = userFound.getPrincipals();
            boolean r = principals.containsAll(principalsFound);
            boolean s = principalsFound.containsAll(principals);
            Set privCredentials = user.getPrivateCredentials();
            Set privCredentialsFound = userFound.getPrivateCredentials();
            boolean t = privCredentials.containsAll(privCredentialsFound);
            boolean u = privCredentialsFound.containsAll(privCredentials);
            assertTrue(user.equals(userFound));
        } catch (AuthenticationException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testUserAlreadyExists() {

        logger.info("begin testUserAlreadyExists");
        String loginAndPassword = DUMMY_LOGIN + System.currentTimeMillis();
        SubjectTemplate st = buildSubjectTemplate(loginAndPassword);
        Subject user = st.toSubject(authenticationManager.getDefaultOrganization());
        try {
            assertFalse(authenticationManager.userAlreadyExists(user));
            authenticationManager.createUser(st, authenticationManager.getDefaultOrganization());
            assertTrue(authenticationManager.userAlreadyExists(user));
        } catch (AuthenticationException ex) {
            Assert.fail(ex.getMessage());
        }

    }

    @Test
    public void testCreateUserWithEmptySubjectTemplate() {

        logger.info("begin testCreateUserWithEmptySubjectTemplate");
        SubjectTemplate st = new SubjectTemplate();
        st.setPrivateOptionalCredentials(new HashSet<JGuardCredential>());
        st.setPublicOptionalCredentials(new HashSet<JGuardCredential>());
        st.setPublicRequiredCredentials(new HashSet<JGuardCredential>());
        st.setPrivateRequiredCredentials(new HashSet<JGuardCredential>());
        st.setPrincipals(new HashSet<Principal>());
        try {
            authenticationManager.createUser(st, authenticationManager.getDefaultOrganization());
        } catch (AuthenticationException e) {
            logger.info(" test succeeed => an exception is the normal result login and password private credentials are required " + e.getMessage());
        }
    }

    @Test
    public void testDeletePrincipal() {

        logger.info("begin testDeletePrincipal");
        Principal ppal = buildRolePrincipal();
        try {
            boolean result = authenticationManager.deletePrincipal(ppal);
        } catch (AuthenticationException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testFindOrganization() {

        Organization orga = authenticationManager.findOrganization(AuthenticationManager.SYSTEM);
        assertNotNull(orga);
    }

    @Test
    public void testRemoveUser() {

        Set<Subject> users = null;
        try {
            users = authenticationManager.getUsers();
        } catch (AuthenticationException e) {
            Assert.fail(" authenticationManager.getUsers()!! " + e.getMessage());
        }
        logger.info(users.toString());
        String loginAndPassword = DUMMY_LOGIN + System.currentTimeMillis();
        SubjectTemplate st = buildSubjectTemplate(loginAndPassword);
        Set<JGuardCredential> reqCreds = st.getRequiredCredentials();
        JGuardCredential jcred1 = null;
        for (JGuardCredential jGuardCredential : reqCreds) {
            if (LOGIN.equals(jGuardCredential.getName())) {
                jcred1 = jGuardCredential;
                break;
            }
        }
        Subject userCreated = null;
        try {
            authenticationManager.createUser(st, authenticationManager.getDefaultOrganization());
            userCreated = authenticationManager.findUser((String) jcred1.getValue());
        } catch (AuthenticationException e) {
            Assert.fail(" user creation fail!! " + e.getMessage());
        }

        try {
            authenticationManager.deleteUser(userCreated);
        } catch (AuthenticationException e) {
            Assert.fail(" remove user  fail!! " + e.getMessage());
        }
        Set<JGuardCredential> coll = new HashSet<JGuardCredential>();
        coll.add(jcred1);
        try {
            Collection usersFound = authenticationManager.findUsers(coll, new ArrayList<JGuardCredential>());
            logger.info(usersFound.toString());
        } catch (AuthenticationException e) {
            Assert.fail(" remove user  fail!! " + e.getMessage());
        }
    }

    @Test
    public void testFindUsers() {


        Set<Subject> users = null;
        try {
            users = authenticationManager.getUsers();
        } catch (AuthenticationException e) {
            Assert.fail(" testFindUsers!! " + e.getMessage());
        }
        Iterator itUsers = users.iterator();
        if (itUsers.hasNext()) {
            try {
                Subject user = (Subject) itUsers.next();
                Collection usersFound = authenticationManager.findUsers(user.getPrivateCredentials(JGuardCredential.class), user.getPublicCredentials(JGuardCredential.class));
                assertTrue(usersFound.size() == 1);
            } catch (AuthenticationException ex) {
                Assert.fail(" testFindUsers!! " + ex.getMessage());
            }
        }
    }

    @Test
    public void testUpdateOrganization() {
        try {

            Organization orga = authenticationManager.findOrganization(AuthenticationManager.SYSTEM);
            Organization orgaCloned = (Organization) orga.clone();
            Collection credentials = orgaCloned.getCredentials();
            String id = "systemCloned" + System.currentTimeMillis();
            JGuardCredential oldCredential = null;
            JGuardCredential idCredential = null;
            for (Object credential : credentials) {
                JGuardCredential cred = (JGuardCredential) credential;
                if (cred.getName().equals(ID)) {
                    idCredential = new JGuardCredential(ID, id);
                    oldCredential = cred;
                    break;
                }
            }
            orgaCloned.getCredentials().remove(oldCredential);
            orgaCloned.getCredentials().add(idCredential);
            Organization clone = authenticationManager.createOrganization(new OrganizationTemplate(orgaCloned));
            Collection<JGuardCredential> creds = clone.getCredentials();
            JGuardCredential cred = new JGuardCredential("stuf", "999999");
            creds.add(cred);
            authenticationManager.updateOrganization(id, clone);
        } catch (AuthenticationException ex) {
            Assert.fail(ex.getMessage());
        } catch (CloneNotSupportedException ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testUpdateUnknownPrincipal() {

        logger.info("begin testUpdateUnknownPrincipal");
        Organization orga = authenticationManager.findOrganization(AuthenticationManager.SYSTEM);
        RolePrincipal principal = new RolePrincipal("myLocalName", "myApplicationName", orga);
        try {
            authenticationManager.updatePrincipal("qsdqsd", principal);
        } catch (AuthenticationException e) {
            Assert.fail();
        }
    }

    @Test
    public void testUpdateUser() {

        logger.info("begin testUpdateUser");
        String loginAndPassword = DUMMY_LOGIN + System.currentTimeMillis();
        int initialSize = authenticationManager.getUsers().size();
        Subject user = createUser(authenticationManager, loginAndPassword);
        int sizeAfterUserCreation = authenticationManager.getUsers().size();
        Assert.assertTrue(sizeAfterUserCreation == initialSize + 1);
        logger.info("user created = " + user.toString());
        Subject foundUser = authenticationManager.findUser(loginAndPassword);
        logger.info("user found after creation = " + foundUser.toString());
        JGuardCredential identityCred = SubjectUtils.getIdentityCredential(user, authenticationManager);
        boolean credentialToUpdateIsPublic = true;
        SubjectUtils.setCredentialValue(user, credentialToUpdateIsPublic, LOGIN, DUMMY_LOGIN, true);
        try {
            authenticationManager.updateUser(identityCred, user);
        } catch (AuthenticationException e) {
            Assert.fail(" update user  fail!! " + e.getMessage());
        }
        int sizeAfterUserUpdated = authenticationManager.getUsers().size();
        Assert.assertTrue(sizeAfterUserCreation == sizeAfterUserUpdated);
        Subject updatedUser = authenticationManager.findUser(DUMMY_LOGIN);
        Assert.assertNotNull(updatedUser);
        JGuardCredential jGuardCredential = SubjectUtils.getIdentityCredential(updatedUser, authenticationManager);
        Assert.assertEquals(DUMMY_LOGIN, jGuardCredential.getValue());


    }

    private Principal buildRolePrincipal() {

        return PrincipalUtils.getPrincipal(RolePrincipal.class.getName(), RolePrincipal.getName("stuff"));
    }

    private SubjectTemplate buildSubjectTemplate(String loginAndPassword) {

        SubjectTemplate st = new SubjectTemplate();
        JGuardCredential jcred1 = new JGuardCredential(LOGIN, loginAndPassword);

        Set<JGuardCredential> pubRequiredCred = new HashSet<JGuardCredential>();
        pubRequiredCred.add(jcred1);
        st.setPublicRequiredCredentials(pubRequiredCred);

        Set<JGuardCredential> privRequiredCred = new HashSet<JGuardCredential>();
        JGuardCredential jcred2 = new JGuardCredential(PASSWORD, loginAndPassword);
        JGuardCredential active = new JGuardCredential(ACTIVE, Boolean.TRUE.toString());
        privRequiredCred.add(jcred2);
        privRequiredCred.add(active);
        st.setPrivateRequiredCredentials(privRequiredCred);
        return st;
    }

    protected Subject createUser(AuthenticationManager auth, String loginAndPassword) {

        logger.info("begin createUser");

        SubjectTemplate st = buildSubjectTemplate(loginAndPassword);
        Subject user = null;
        try {
            user = auth.createUser(st, auth.getDefaultOrganization());
        } catch (AuthenticationException e) {
            Assert.fail(e.getMessage());
        }
        return user;
    }


}
