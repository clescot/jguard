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
package net.sf.jguard.ext.principals;

import junit.framework.Assert;
import junit.framework.TestCase;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authorization.permissions.PermissionUtils;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.core.principals.PrincipalUtils;
import net.sf.jguard.core.principals.RolePrincipal;
import net.sf.jguard.core.principals.UserPrincipal;
import org.bouncycastle.jce.X509Principal;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.x500.X500Principal;
import java.io.FilePermission;
import java.security.*;
import java.util.Enumeration;

public class PrincipalUtilsTest extends TestCase {

    private static final Logger logger = LoggerFactory.getLogger(PrincipalUtilsTest.class.getName());
    private static final String NAME = "name";
    private static final String USER_A = "userA";
    private static final String USER_B = "userB";
    private static final String COMPANY = "company";
    private static final String COMPANY_A = "companyA";
    private static final String COMPANY_B = "companyB";
    private static final String AGE = "age";
    private static final String DUMMY_AGE = "100";

    /*
      * Test method for 'net.sf.jguard.core.principals.PrincipalUtils.getPrincipal(String, String)'
      */
    @Test
    public void testGetPrincipal() {
        //we test jGuardPrincipal
        Principal ppal = PrincipalUtils.getPrincipal(RolePrincipal.class.getName(), RolePrincipal.getName("stuff"));
        Assert.assertEquals(RolePrincipal.class, ppal.getClass());
        Assert.assertEquals("*#stuff", ppal.getName());

        //we test X509Principal
        Principal ppal2 = PrincipalUtils.getPrincipal(X509Principal.class.getName(), "C=AU,ST=Victoria");
        Assert.assertEquals(org.bouncycastle.jce.X509Principal.class, ppal2.getClass());

        //we test X500Principal
        Principal ppal3 = PrincipalUtils.getPrincipal(X500Principal.class.getName(), "C=AU,ST=Victoria");
        Assert.assertEquals(javax.security.auth.x500.X500Principal.class, ppal3.getClass());

//        we test KerberosPrincipal
        Principal ppal4 = PrincipalUtils.getPrincipal(KerberosPrincipal.class.getName(), "duke@FOO.COM");
        Assert.assertEquals(javax.security.auth.kerberos.KerberosPrincipal.class, ppal4.getClass());
    }

    public void testEvaluateCombinativePermissionCollection() throws Throwable {
        PermissionUtils.setCachesEnabled(true);
        PermissionUtils.createCaches();

        Subject subject = new Subject();

        JGuardCredential nameA = new JGuardCredential(NAME, USER_A);
        JGuardCredential nameB = new JGuardCredential(NAME, USER_B);
        JGuardCredential companyA = new JGuardCredential(COMPANY, COMPANY_A);
        JGuardCredential companyB = new JGuardCredential(COMPANY, COMPANY_B);
        JGuardCredential age = new JGuardCredential(AGE, DUMMY_AGE);

        subject.getPublicCredentials().add(nameA);
        subject.getPublicCredentials().add(nameB);
        subject.getPublicCredentials().add(companyA);
        subject.getPublicCredentials().add(companyB);
        subject.getPublicCredentials().add(age);

        if (logger.isDebugEnabled()) {
            logger.debug("---- logging subject ----");
            logger.debug(subject.toString());
        }

        UserPrincipal userPrincipal = new UserPrincipal(subject);

        ProtectionDomain protectionDomain = new ProtectionDomain(null, new Permissions(), null, new Principal[]{userPrincipal});

        PermissionCollection pc = new Permissions();
        Permission p1 = new FilePermission("file://home", "read");
        Permission p2 = new FilePermission("file://home/user/${subject.publicCredentials.name}", "read");
        Permission p3 = new FilePermission("file://home/user/${subject.publicCredentials.company}", "read");
        Permission p4 = new FilePermission("file://home/user/${subject.publicCredentials.name}/" +
                "${subject.publicCredentials.company}/${subject.publicCredentials.age}", "read");
        Permission p5 = new FilePermission("file://home/user/${subject.publicCredentials.company}/${subject.publicCredentials.company}", "read");
        Permission p6 = new URLPermission("index", "http://www.website.com/index.html?name=${subject.publicCredentials.name}&company=${subject.publicCredentials.company}&age=${subject.publicCredentials.age}");

        pc.add(p1);
        pc.add(p2);
        pc.add(p3);
        pc.add(p4);
        pc.add(p5);
        pc.add(p6);

        if (logger.isDebugEnabled()) {
            logger.debug("---- logging unresolved permissions ----");
            Enumeration unresolvedPermEnum = pc.elements();
            while (unresolvedPermEnum.hasMoreElements()) {
                logger.debug(unresolvedPermEnum.nextElement().toString());
            }
        }

        PermissionCollection expectedPc = new Permissions();
        Permission expectedP1 = new FilePermission("file://home", "read");
        Permission expectedP2a = new FilePermission("file://home/user/userA", "read");
        Permission expectedP2b = new FilePermission("file://home/user/userB", "read");
        Permission expectedP3a = new FilePermission("file://home/user/companyA", "read");
        Permission expectedP3b = new FilePermission("file://home/user/companyB", "read");
        Permission expectedP4a = new FilePermission("file://home/user/userA/companyA/100", "read");
        Permission expectedP4b = new FilePermission("file://home/user/userA/companyB/100", "read");
        Permission expectedP4c = new FilePermission("file://home/user/userB/companyA/100", "read");
        Permission expectedP4d = new FilePermission("file://home/user/userB/companyB/100", "read");
        Permission expectedP5a = new FilePermission("file://home/user/companyA/companyA", "read");
        Permission expectedP5b = new FilePermission("file://home/user/companyA/companyB", "read");
        Permission expectedP5c = new FilePermission("file://home/user/companyB/companyA", "read");
        Permission expectedP5d = new FilePermission("file://home/user/companyB/companyB", "read");
        Permission expectedP6a = new URLPermission("index", "http://www.website.com/index.html?name=userA&company=companyA&age=100");
        Permission expectedP6b = new URLPermission("index", "http://www.website.com/index.html?name=userA&company=companyB&age=100");
        Permission expectedP6c = new URLPermission("index", "http://www.website.com/index.html?name=userB&company=companyA&age=100");
        Permission expectedP6d = new URLPermission("index", "http://www.website.com/index.html?name=userB&company=companyB&age=100");

        expectedPc.add(expectedP1);
        expectedPc.add(expectedP2a);
        expectedPc.add(expectedP2b);
        expectedPc.add(expectedP3a);
        expectedPc.add(expectedP3b);
        expectedPc.add(expectedP4a);
        expectedPc.add(expectedP4b);
        expectedPc.add(expectedP4c);
        expectedPc.add(expectedP4d);
        expectedPc.add(expectedP5a);
        expectedPc.add(expectedP5b);
        expectedPc.add(expectedP5c);
        expectedPc.add(expectedP5d);
        expectedPc.add(expectedP6a);
        expectedPc.add(expectedP6b);
        expectedPc.add(expectedP6c);
        expectedPc.add(expectedP6d);

        // getting resolved permissions
        PermissionCollection resolvedPc = PrincipalUtils.evaluatePermissionCollection(protectionDomain, pc);

        if (logger.isDebugEnabled()) {
            logger.debug("---- logging expected permissions ----");
            Enumeration expectedPermEnum = expectedPc.elements();
            while (expectedPermEnum.hasMoreElements()) {
                logger.debug(expectedPermEnum.nextElement().toString());
            }

            logger.debug("---- logging resolved permissions ----");
        }

        int collectionSize = 0;
        Enumeration permEnum = resolvedPc.elements();
        while (permEnum.hasMoreElements()) {
            Permission resolvedPerm = (Permission) permEnum.nextElement();
            logger.debug("verify implies for " + resolvedPerm.toString());
            System.out.println("verify implies for " + resolvedPerm.toString());
            assertTrue(expectedPc.implies(resolvedPerm));
            collectionSize++;
        }
        assertEquals(17, collectionSize);
        System.out.println("END EVALUATE COMBINATIVE PERMISSION TEST");

    }

    public void testEvaluatePermissionCollection() throws Throwable {
        PermissionUtils.setCachesEnabled(true);
        PermissionUtils.createCaches();

        Subject subjectA = new Subject();

        JGuardCredential nameA = new JGuardCredential(NAME, USER_A);
        JGuardCredential companyA = new JGuardCredential(COMPANY, COMPANY_A);

        subjectA.getPublicCredentials().add(nameA);
        subjectA.getPublicCredentials().add(companyA);

        if (logger.isDebugEnabled()) {
            logger.debug("---- logging subject ----");
            logger.debug(subjectA.toString());
        }

        UserPrincipal userPrincipal = new UserPrincipal(subjectA);

        ProtectionDomain protectionDomain = new ProtectionDomain(null, new Permissions(), null, new Principal[]{userPrincipal});

        PermissionCollection pc = new Permissions();
        Permission p1 = new FilePermission("file://home", "read");
        Permission p2 = new FilePermission("file://home/user/${subject.publicCredentials.name}", "read");
        Permission p3 = new FilePermission("file://home/user/${subject.publicCredentials.company}", "read");
        Permission p4 = new FilePermission("file://home/user/${subject.publicCredentials.name}/" +
                "${subject.publicCredentials.company}/${subject.publicCredentials.name}/" +
                "${subject.publicCredentials.name}/${subject.publicCredentials.company}", "read");
        Permission p5 = new FilePermission("file://home/user/${subject.publicCredentials.age}", "read");
        Permission p6 = new URLPermission("index", "http://www.website.com/index.html?name=${subject.publicCredentials.name}");
        Permission p7 = new URLPermission("index2", "http://www.web�site.com/index.html?name=${subject.publicCredentials.name}");

        pc.add(p1);
        pc.add(p2);
        pc.add(p3);
        pc.add(p4);
        pc.add(p5);
        pc.add(p6);
        pc.add(p7);

        if (logger.isDebugEnabled()) {
            logger.debug("---- logging unresolved permissions ----");
            Enumeration unresolvedPermEnum = pc.elements();
            while (unresolvedPermEnum.hasMoreElements()) {
                logger.debug(unresolvedPermEnum.nextElement().toString());
            }
        }

        PermissionCollection expectedPc = new Permissions();
        Permission expectedP1 = new FilePermission("file://home", "read");
        Permission expectedP2 = new FilePermission("file://home/user/userA", "read");
        Permission expectedP3 = new FilePermission("file://home/user/companyA", "read");
        Permission expectedP4 = new FilePermission("file://home/user/userA/companyA/userA/userA/companyA", "read");
        Permission expectedP6 = new URLPermission("index", "http://www.website.com/index.html?name=userA");
        Permission expectedP7 = new URLPermission("index2", "http://www.web�site.com/index.html?name=userA");

        expectedPc.add(expectedP1);
        expectedPc.add(expectedP2);
        expectedPc.add(expectedP3);
        expectedPc.add(expectedP4);
        expectedPc.add(expectedP6);
        expectedPc.add(expectedP7);

        // getting resolved permissions
        PermissionCollection resolvedPc = PrincipalUtils.evaluatePermissionCollection(protectionDomain, pc);

        if (logger.isDebugEnabled()) {
            logger.debug("---- logging expected permissions ----");
            Enumeration expectedPermEnum = expectedPc.elements();
            while (expectedPermEnum.hasMoreElements()) {
                logger.debug(expectedPermEnum.nextElement().toString());
            }

            logger.debug("---- logging resolved permissions ----");
        }

        int collectionSize = 0;
        Enumeration permEnum = resolvedPc.elements();
        while (permEnum.hasMoreElements()) {
            Permission resolvedPerm = (Permission) permEnum.nextElement();
            logger.debug("verify implies for " + resolvedPerm.toString());
            System.out.println("verify implies for " + resolvedPerm.toString());
            assertTrue(expectedPc.implies(resolvedPerm));
            collectionSize++;
        }
        assertEquals(6, collectionSize);
        System.out.println("END EVALUATE PERMISSION TEST");
    }


}
