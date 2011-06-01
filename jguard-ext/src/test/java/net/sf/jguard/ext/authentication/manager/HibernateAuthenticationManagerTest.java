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


import javax.inject.Inject;
import com.google.inject.Module;
import com.google.inject.Provider;
import com.mycila.testing.junit.MycilaJunitRunner;
import com.mycila.testing.plugin.guice.ModuleProvider;
import com.wideplay.warp.persist.PersistenceService;
import com.wideplay.warp.persist.UnitOfWork;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.test.AuthenticationManagerTest;
import net.sf.jguard.core.test.JGuardTestFiles;
import net.sf.jguard.core.util.SubjectUtils;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import java.util.ArrayList;
import java.util.Collection;


/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
@RunWith(MycilaJunitRunner.class)
public class HibernateAuthenticationManagerTest extends AuthenticationManagerTest {


    private static Logger logger = LoggerFactory.getLogger(HibernateAuthenticationManagerTest.class);

    @Inject
    protected Provider<Session> session;

    @Inject
    public PersistenceService persistenceService;

    @Before
    public void setUp() throws Exception {

    }

    @ModuleProvider
    public Iterable<Module> providesAuthenticationManagerModule() {
        Collection<Module> list = new ArrayList<Module>();
        list.add(new HibernateAuthenticationManagerModule(JGuardTestFiles.JGUARD_STRUTS_EXAMPLE.getLabel(), url));
        list.add(PersistenceService.usingHibernate().across(UnitOfWork.REQUEST).buildModule());
        return list;


    }

    static class PersistenceServiceInitializer {

        @Inject
        public PersistenceServiceInitializer(final PersistenceService service) {
            service.start();
        }
    }

    @Test
    public void testAddAndRemoveRolePrincipal() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testAddAndRemoveRolePrincipal();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }
    }

    @Test
    public void testCreateOrganization() throws CloneNotSupportedException {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testCreateOrganization();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }
    }

    @Test
    public void testCreateUser() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testCreateUser();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }
    }

    @Test
    public void testUserAlreadyExists() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testUserAlreadyExists();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }
    }

    @Test
    public void testCreateUserWithEmptySubjectTemplate() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testCreateUserWithEmptySubjectTemplate();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }
    }

    @Test
    public void testDeletePrincipal() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testDeletePrincipal();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }

    }

    @Test
    public void testFindOrganization() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testFindOrganization();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }
    }

    @Test
    public void testCreateAndRemoveUser() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testCreateAndRemoveUser();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }

    }

    @Test
    public void testUpdateUser() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            logger.info("begin testUpdateUser");
            String loginAndPassword = DUMMY_LOGIN + System.currentTimeMillis();
            Subject user = createUser(authenticationManager, loginAndPassword);
            logger.info("user created = " + user.toString());
            tx.commit();

            tx = session.get().beginTransaction();
            Subject foundUser = authenticationManager.findUser(loginAndPassword);
            logger.info("user found after creation = " + foundUser.toString());

            JGuardCredential identityCred = SubjectUtils.getIdentityCredential(foundUser, authenticationManager);
            //identity credential is always part of the public subject credential set
            SubjectUtils.setCredentialValue(foundUser, true, LOGIN, DUMMY_LOGIN, true);
            session.get().evict(foundUser);
            try {
                authenticationManager.updateUser(identityCred, foundUser);
            } catch (AuthenticationException e) {
                Assert.fail(" update user  fail!! " + e.getMessage());
            }
            tx.commit();
            tx = session.get().beginTransaction();
            Subject updatedUser = authenticationManager.findUser(DUMMY_LOGIN);
            Assert.assertNotNull(updatedUser);
            JGuardCredential jGuardCredential = SubjectUtils.getIdentityCredential(updatedUser, authenticationManager);
            Assert.assertEquals(DUMMY_LOGIN, jGuardCredential.getValue());
            tx.commit();
        } finally {
            if (tx != null && tx.isActive()) {
                tx.rollback();
            }
        }
    }

    @Test
    public void testUpdateOrganization() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testUpdateOrganization();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }
    }

    @Test
    public void testUpdateUnknownPrincipal() {

        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testUpdateUnknownPrincipal();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }

    }

    @Test
    public void testRemoveUser() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testRemoveUser();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }
    }

    @Test
    public void testFindUsers() {
        Transaction tx = null;
        try {
            tx = session.get().beginTransaction();
            super.testFindUsers();
        } finally {
            if (tx != null) {
                tx.rollback();
            }
        }
    }

    @After
    public void tearDown() throws Exception {
        session.get().close();
    }

}
